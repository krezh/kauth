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

	"kauth/pkg/handlers"
	"kauth/pkg/jwt"
	"kauth/pkg/middleware"
	"kauth/pkg/oauth"
	"kauth/pkg/server"
	"kauth/pkg/session"
	"kauth/pkg/validation"

	"github.com/prometheus/client_golang/prometheus/promhttp"
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
		IssuerURL:        getEnv("OIDC_ISSUER_URL", ""),
		ClientID:         getEnv("OIDC_CLIENT_ID", ""),
		ClientSecret:     getEnv("OIDC_CLIENT_SECRET", ""),
		ClusterName:      clusterName,
		BaseURL:          getEnv("BASE_URL", ""),
		ListenAddr:       getEnv("LISTEN_ADDR", ":8080"),
		TLSCertFile:      getEnv("TLS_CERT_FILE", ""),
		TLSKeyFile:       getEnv("TLS_KEY_FILE", ""),
		JWTSigningKey:    jwtSigningKey,
		JWTEncryptionKey: jwtEncryptionKey,
		SessionTTL:       getEnvDuration("SESSION_TTL", 15*time.Minute),
		RefreshTokenTTL:  getEnvDuration("REFRESH_TOKEN_TTL", 7*24*time.Hour),
		AllowedOrigins:   getEnvStringSlice("ALLOWED_ORIGINS", []string{}),
		AllowedGroups:    getEnvStringSlice("ALLOWED_GROUPS", []string{}),
		RateLimitRPS:     getEnvFloat("RATE_LIMIT_RPS", 10.0),
		RateLimitBurst:   getEnvInt("RATE_LIMIT_BURST", 20),
		RotationWindow:   getEnvInt("ROTATION_WINDOW", 2),
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

	// Initialize OIDC provider with retries
	var provider *oauth.Provider
	maxRetries := 60
	retryDelay := 5 * time.Second
	maxRetryDelay := 2 * time.Minute

	for attempt := 1; attempt <= maxRetries; attempt++ {
		provider, err = oauth.NewProvider(ctx, oauth.Config{
			IssuerURL:    cfg.IssuerURL,
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.BaseURL + "/callback",
		})
		if err == nil {
			slog.Info("Successfully connected to OIDC provider", "url", cfg.IssuerURL)
			break
		}

		slog.Warn("Failed to connect to OIDC provider", "attempt", attempt, "max_attempts", maxRetries, "error", err)

		if attempt == maxRetries {
			slog.Error("Failed to setup OIDC provider, giving up", "attempts", maxRetries)
			os.Exit(1)
		}

		// Exponential backoff with max delay
		currentDelay := retryDelay * time.Duration(attempt)
		if currentDelay > maxRetryDelay {
			currentDelay = maxRetryDelay
		}

		slog.Info("Retrying OIDC connection", "delay", currentDelay)
		time.Sleep(currentDelay)
	}

	loginHandler := handlers.NewLoginHandler(
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

	refreshHandler := handlers.NewRefreshHandler(
		provider,
		jwtManager,
		cfg.ClusterName,
		clusterServer,
		clusterCA,
		cfg.RefreshTokenTTL,
		cfg.RotationWindow,
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/info", handlers.HandleInfo(
		cfg.ClusterName,
		clusterServer,
		cfg.IssuerURL,
		cfg.ClientID,
		cfg.BaseURL,
	))
	mux.HandleFunc("/start-login", loginHandler.HandleStartLogin)
	mux.HandleFunc("/watch", loginHandler.HandleWatch)
	mux.HandleFunc("/callback", loginHandler.HandleCallback)
	mux.HandleFunc("/refresh", refreshHandler.HandleRefresh)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})
	mux.Handle("/metrics", promhttp.Handler())

	// Apply middleware
	var handler http.Handler = mux

	// Request ID (must be first to ensure all logs have request ID)
	handler = middleware.RequestID(handler)

	// Request logging
	handler = middleware.RequestLogger(handler)

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
	rateLimiter := middleware.NewRateLimiter(cfg.RateLimitRPS, cfg.RateLimitBurst, 5*time.Minute)
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

	// Create HTTP server
	server := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: handler,
	}

	// Channel to listen for errors from server
	serverErrors := make(chan error, 1)

	// Start server in goroutine
	go func() {
		if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
			slog.Info("Starting server with TLS")
			serverErrors <- server.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
		} else {
			slog.Info("Starting server without TLS", "hint", "Use TLS_CERT_FILE and TLS_KEY_FILE for HTTPS")
			serverErrors <- server.ListenAndServe()
		}
	}()

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
		slog.Info("Invalid duration for %s: %s, using default", key, value)
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
		slog.Info("Invalid int for %s: %s, using default", key, value)
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
		slog.Info("Invalid float for %s: %s, using default", key, value)
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
