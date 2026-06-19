package main

import (
	"context"
	"encoding/base64"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"kauth/pkg/audit"
	"kauth/pkg/handlers"
	"kauth/pkg/jwt"
	"kauth/pkg/middleware"
	"kauth/pkg/oauth"
	"kauth/pkg/server"
	"kauth/pkg/session"
	"kauth/pkg/validation"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	// Initialize structured logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	slog.Info("Starting kauth-server")

	// Load JWT keys from environment (REQUIRED)
	jwtSigningKey := getEnvBytes("JWT_SIGNING_KEY")
	jwtEncryptionKey := getEnvBytes("JWT_ENCRYPTION_KEY")

	if len(jwtSigningKey) == 0 || len(jwtEncryptionKey) == 0 {
		slog.Error("JWT keys are required",
			"error", "JWT_SIGNING_KEY and JWT_ENCRYPTION_KEY must be set",
			"hint", "Generate with: openssl rand -base64 32")
		os.Exit(1)
	}

	if len(jwtSigningKey) < 32 {
		slog.Error("JWT_SIGNING_KEY too short", "min_bytes", 32, "actual_bytes", len(jwtSigningKey))
		os.Exit(1)
	}

	if len(jwtEncryptionKey) != 32 {
		slog.Error("JWT_ENCRYPTION_KEY wrong size", "required_bytes", 32, "actual_bytes", len(jwtEncryptionKey))
		os.Exit(1)
	}

	// Validate cluster name
	clusterName := getEnv("CLUSTER_NAME", "kubernetes")
	if err := validation.ValidateResourceName(clusterName); err != nil {
		slog.Error("Invalid CLUSTER_NAME", "error", err, "hint", "Cluster name must be lowercase alphanumeric with hyphens or dots (RFC 1123), max 63 characters")
		os.Exit(1)
	}

	cfg := server.Config{
		IssuerURL:          getEnv("OIDC_ISSUER_URL", ""),
		ClientID:           getEnv("OIDC_CLIENT_ID", ""),
		ClientSecret:       getEnv("OIDC_CLIENT_SECRET", ""),
		ClusterName:        clusterName,
		BaseURL:            getEnv("BASE_URL", ""),
		ListenAddr:         getEnv("LISTEN_ADDR", ":8080"),
		TLSCertFile:        getEnv("TLS_CERT_FILE", ""),
		TLSKeyFile:         getEnv("TLS_KEY_FILE", ""),
		WebhookListenAddr: getEnv("WEBHOOK_LISTEN_ADDR", ""),
		JWTSigningKey:      jwtSigningKey,
		JWTEncryptionKey:   jwtEncryptionKey,
		SessionTTL:         getEnvDuration("SESSION_TTL", 15*time.Minute),
		RefreshTokenTTL:    getEnvDuration("REFRESH_TOKEN_TTL", 7*24*time.Hour),
		AllowedOrigins:     getEnvStringSlice("ALLOWED_ORIGINS", []string{}),
		AllowedGroups:      getEnvStringSlice("ALLOWED_GROUPS", []string{}),
		AdminGroups:        getEnvStringSlice("ADMIN_GROUPS", []string{}),
		RateLimitRPS:       getEnvFloat("RATE_LIMIT_RPS", 10.0),
		RateLimitBurst:     getEnvInt("RATE_LIMIT_BURST", 20),
		RotationWindow:     getEnvInt("ROTATION_WINDOW", 2),
		TrustedProxyCIDRs:  getEnvStringSlice("TRUSTED_PROXY_CIDRS", []string{}),
	}

	if cfg.IssuerURL == "" || cfg.ClientID == "" || cfg.ClientSecret == "" {
		slog.Error("Required OIDC configuration missing", "error", "OIDC_ISSUER_URL, OIDC_CLIENT_ID, and OIDC_CLIENT_SECRET are required")
		os.Exit(1)
	}

	if cfg.BaseURL == "" {
		slog.Error("BASE_URL is required", "hint", "e.g. https://kauth.example.com")
		os.Exit(1)
	}

	// Get cluster API endpoint URL (must be set manually)
	clusterServer := getEnv("KUBERNETES_API_URL", "")
	if clusterServer == "" {
		slog.Error("KUBERNETES_API_URL is required", "hint", "e.g. https://kubernetes.example.com:6443")
		os.Exit(1)
	}
	slog.Info("Cluster API URL", "url", clusterServer)

	// Auto-detect cluster CA (from env or in-cluster mount)
	clusterCA, err := server.GetClusterCA()
	if err != nil {
		slog.Error("Failed to get cluster CA", "error", err)
		os.Exit(1)
	}
	slog.Info("Cluster CA loaded successfully")

	// Initialize JWT manager
	jwtManager, err := jwt.NewManager(cfg.JWTSigningKey, cfg.JWTEncryptionKey)
	if err != nil {
		slog.Error("Failed to initialize JWT manager", "error", err)
		os.Exit(1)
	}
	slog.Info("JWT manager initialized")

	ctx := context.Background()

	// Initialize Kubernetes client
	k8sConfig, err := getK8sConfig()
	if err != nil {
		slog.Error("Failed to get Kubernetes config", "error", err)
		os.Exit(1)
	}

	// Create session client for managing OAuthSession CRDs
	namespace := getEnv("KAUTH_NAMESPACE", "default")
	sessionClient, err := session.NewClient(k8sConfig, namespace)
	if err != nil {
		slog.Error("Failed to create session client", "error", err)
		os.Exit(1)
	}
	slog.Info("Session client initialized", "namespace", namespace)

	// Initialize OIDC provider in background with retries
	var provider *oauth.Provider
	providerReady := make(chan struct{})

	// Handlers are initialized inside the goroutine before close(providerReady).
	// The channel close establishes a happens-before guarantee, so any goroutine
	// that reads from providerReady sees fully-initialized handler values.
	var loginHandler *handlers.LoginHandler
	var refreshHandler *handlers.RefreshHandler

	webhookHandler := handlers.NewWebhookHandler(jwtManager, sessionClient)

	go func() {
		maxRetries := 60
		retryDelay := 5 * time.Second
		maxRetryDelay := 2 * time.Minute

		for attempt := 1; attempt <= maxRetries; attempt++ {
			p, err := oauth.NewProvider(ctx, oauth.Config{
				IssuerURL:    cfg.IssuerURL,
				ClientID:     cfg.ClientID,
				ClientSecret: cfg.ClientSecret,
				RedirectURL:  cfg.BaseURL + "/callback",
			})
			if err == nil {
				provider = p
				loginHandler = handlers.NewLoginHandler(
					provider,
					jwtManager,
					cfg.ClusterName,
					clusterServer,
					clusterCA,
					cfg.SessionTTL,
					cfg.RefreshTokenTTL,
					cfg.AllowedGroups,
					sessionClient,
				)
				refreshHandler = handlers.NewRefreshHandler(
					provider,
					jwtManager,
					sessionClient,
					cfg.ClusterName,
					clusterServer,
					clusterCA,
					cfg.RefreshTokenTTL,
					cfg.RotationWindow,
				)
				close(providerReady)
				slog.Info("Successfully connected to OIDC provider", "url", cfg.IssuerURL)
				return
			}

			slog.Warn("Failed to connect to OIDC provider", "attempt", attempt, "max_attempts", maxRetries, "error", err)

			if attempt == maxRetries {
				slog.Error("Failed to setup OIDC provider after all retries", "attempts", maxRetries)
				return
			}

			// Exponential backoff with max delay
			currentDelay := retryDelay * time.Duration(attempt)
			if currentDelay > maxRetryDelay {
				currentDelay = maxRetryDelay
			}

			slog.Info("Retrying OIDC connection", "delay", currentDelay)
			time.Sleep(currentDelay)
		}
	}()

	mux := http.NewServeMux()

	// Middleware to check if OIDC provider is ready
	requireProvider := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-providerReady:
				// Provider is ready, proceed
				next(w, r)
			default:
				// Provider not ready yet
				http.Error(w, "Service temporarily unavailable: OIDC provider initializing", http.StatusServiceUnavailable)
			}
		}
	}

	mux.HandleFunc("/info", handlers.HandleInfo(
		cfg.ClusterName,
		clusterServer,
		cfg.IssuerURL,
		cfg.ClientID,
		cfg.BaseURL,
	))
	mux.HandleFunc("/start-login", requireProvider(func(w http.ResponseWriter, r *http.Request) {
		loginHandler.HandleStartLogin(w, r)
	}))
	mux.HandleFunc("/watch", requireProvider(func(w http.ResponseWriter, r *http.Request) {
		loginHandler.HandleWatch(w, r)
	}))
	mux.HandleFunc("/callback", requireProvider(func(w http.ResponseWriter, r *http.Request) {
		loginHandler.HandleCallback(w, r)
	}))
	mux.HandleFunc("/refresh", requireProvider(func(w http.ResponseWriter, r *http.Request) {
		refreshHandler.HandleRefresh(w, r)
	}))
	mux.HandleFunc("/revoke", requireProvider(handlers.RequireAuth(func() *oauth.Provider { return provider }, func(w http.ResponseWriter, r *http.Request) {
		handlers.NewRevokeHandler(sessionClient, cfg.AdminGroups).HandleRevoke(w, r)
	})))
	mux.HandleFunc("/sessions", requireProvider(handlers.RequireAuth(func() *oauth.Provider { return provider }, func(w http.ResponseWriter, r *http.Request) {
		handlers.NewSessionsHandler(sessionClient, cfg.AdminGroups).HandleListSessions(w, r)
	})))
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	// Apply middleware
	var handler http.Handler = mux

	// IP extraction with trusted proxy support
	ipExtractor := middleware.NewClientIPExtractor(cfg.TrustedProxyCIDRs)

	// Request logging
	handler = middleware.RequestLogger(ipExtractor)(handler)

	// Request ID (applied last, runs first to set context for all other middleware)
	handler = middleware.RequestID(handler)

	// Audit logging
	audit.SetIPExtractor(ipExtractor)

	// Security headers
	handler = middleware.SecurityHeaders(handler)

	// HSTS (only if using TLS)
	if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
		handler = middleware.HSTS(handler)
	}

	// CORS (if origins are specified)
	if len(cfg.AllowedOrigins) > 0 {
		handler = middleware.CORS(cfg.AllowedOrigins)(handler)
	}

	// Rate limiting
	rateLimiter := middleware.NewRateLimiter(cfg.RateLimitRPS, cfg.RateLimitBurst, 5*time.Minute, cfg.TrustedProxyCIDRs)
	handler = rateLimiter.Middleware(handler)

	slog.Info("Starting kauth server",
		"listen_addr", cfg.ListenAddr,
		"base_url", cfg.BaseURL,
		"cluster", cfg.ClusterName,
		"session_ttl", cfg.SessionTTL,
		"refresh_token_ttl", cfg.RefreshTokenTTL,
		"rate_limit_rps", cfg.RateLimitRPS,
		"rate_limit_burst", cfg.RateLimitBurst,
	)

	if len(cfg.AllowedOrigins) > 0 {
		slog.Info("CORS enabled", "origins", cfg.AllowedOrigins)
	}
	if len(cfg.AllowedGroups) > 0 {
		slog.Info("Group authorization enabled", "allowed_groups", cfg.AllowedGroups)
	} else {
		slog.Info("Group authorization disabled - all OIDC users allowed")
	}
	if len(cfg.AdminGroups) > 0 {
		slog.Info("Admin groups configured", "admin_groups", cfg.AdminGroups)
	} else {
		slog.Info("No admin groups configured - session management disabled")
	}

	// Create HTTP server
	server := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: handler,
	}

	// Dedicated HTTP listener for the Kubernetes token-review webhook. Kept
	// separate from the client-facing API so it bypasses the rate limiter (which
	// would throttle burst requests from the API server on pod restart or cache
	// expiry). Application-layer encryption makes in-cluster HTTP safe.
	var webhookServer *http.Server
	if cfg.WebhookListenAddr != "" {
		webhookMux := http.NewServeMux()
		webhookMux.HandleFunc("/webhook/token-review", func(w http.ResponseWriter, r *http.Request) {
			webhookHandler.HandleTokenReview(w, r)
		})
		var webhookHTTPHandler http.Handler = webhookMux
		webhookHTTPHandler = middleware.RequestLogger(ipExtractor)(webhookHTTPHandler)
		webhookHTTPHandler = middleware.RequestID(webhookHTTPHandler)
		webhookServer = &http.Server{
			Addr:    cfg.WebhookListenAddr,
			Handler: webhookHTTPHandler,
		}
	}

	// Channel to listen for errors from server
	serverErrors := make(chan error, 1)

	// Start server in goroutine
	go func() {
		if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
			slog.Info("Starting server with TLS")
			serverErrors <- server.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
		} else {
			serverErrors <- server.ListenAndServe()
		}
	}()

	if webhookServer != nil {
		go func() {
			slog.Info("Starting webhook token-review listener", "listen_addr", cfg.WebhookListenAddr)
			serverErrors <- webhookServer.ListenAndServe()
		}()
	} else {
		slog.Info("Webhook token-review listener disabled (set WEBHOOK_LISTEN_ADDR to enable)")
	}

	// Setup signal handling for graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	// Wait for shutdown signal or server error
	select {
	case err := <-serverErrors:
		slog.Error("Server failed to start", "error", err)
		os.Exit(1)
	case sig := <-stop:
		slog.Info("Shutdown signal received", "signal", sig.String())

		// Create shutdown context with timeout
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Attempt graceful shutdown
		slog.Info("Shutting down server gracefully...")
		if err := server.Shutdown(shutdownCtx); err != nil {
			slog.Error("Server forced to shutdown", "error", err)
			os.Exit(1)
		}
		if webhookServer != nil {
			if err := webhookServer.Shutdown(shutdownCtx); err != nil {
				slog.Error("Webhook listener forced to shutdown", "error", err)
				os.Exit(1)
			}
		}

		slog.Info("Server stopped gracefully")
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvBytes(key string) []byte {
	value := os.Getenv(key)
	if value == "" {
		return nil
	}
	// Try base64 decoding
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err == nil {
		return decoded
	}
	// Fall back to raw bytes
	return []byte(value)
}

func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		slog.Warn("invalid env var, using default", "key", key, "value", value)
		return defaultValue
	}
	return duration
}

func getEnvInt(key string, defaultValue int) int {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	intVal, err := strconv.Atoi(value)
	if err != nil {
		slog.Warn("invalid env var, using default", "key", key, "value", value)
		return defaultValue
	}
	return intVal
}

func getEnvFloat(key string, defaultValue float64) float64 {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	floatVal, err := strconv.ParseFloat(value, 64)
	if err != nil {
		slog.Warn("invalid env var, using default", "key", key, "value", value)
		return defaultValue
	}
	return floatVal
}

func getEnvStringSlice(key string, defaultValue []string) []string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return strings.Split(value, ",")
}

// getK8sConfig returns Kubernetes client config (in-cluster or from kubeconfig)
func getK8sConfig() (*rest.Config, error) {
	// Try in-cluster config first (for pods running in Kubernetes)
	config, err := rest.InClusterConfig()
	if err == nil {
		slog.Info("Using in-cluster Kubernetes config")
		return config, nil
	}

	// Fall back to kubeconfig (for local development)
	kubeconfigPath := os.Getenv("KUBECONFIG")
	if kubeconfigPath == "" {
		kubeconfigPath = os.Getenv("HOME") + "/.kube/config"
	}

	config, err = clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	if err != nil {
		return nil, err
	}

	slog.Info("Using kubeconfig", "path", kubeconfigPath)
	return config, nil
}
