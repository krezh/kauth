package main

import (
	"context"
	"encoding/base64"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"kauth/pkg/handlers"
	"kauth/pkg/jwt"
	"kauth/pkg/middleware"
	"kauth/pkg/oauth"
	"kauth/pkg/server"
)

func main() {
	// Load JWT keys from environment
	jwtSigningKey := getEnvBytes("JWT_SIGNING_KEY")
	jwtEncryptionKey := getEnvBytes("JWT_ENCRYPTION_KEY")

	if len(jwtSigningKey) == 0 || len(jwtEncryptionKey) == 0 {
		log.Println("WARNING: JWT keys not found in environment. Generating random keys.")
		log.Println("For production, set JWT_SIGNING_KEY and JWT_ENCRYPTION_KEY environment variables.")
		log.Println("Generate keys with: openssl rand -base64 32")

		var err error
		jwtSigningKey, err = jwt.GenerateRandomKey(32)
		if err != nil {
			log.Fatalf("Failed to generate signing key: %v", err)
		}
		jwtEncryptionKey, err = jwt.GenerateRandomKey(32)
		if err != nil {
			log.Fatalf("Failed to generate encryption key: %v", err)
		}

		log.Printf("Generated JWT_SIGNING_KEY: %s", base64.StdEncoding.EncodeToString(jwtSigningKey))
		log.Printf("Generated JWT_ENCRYPTION_KEY: %s", base64.StdEncoding.EncodeToString(jwtEncryptionKey))
	}

	cfg := server.Config{
		IssuerURL:        getEnv("OIDC_ISSUER_URL", ""),
		ClientID:         getEnv("OIDC_CLIENT_ID", ""),
		ClientSecret:     getEnv("OIDC_CLIENT_SECRET", ""),
		ClusterName:      getEnv("CLUSTER_NAME", "kubernetes"),
		BaseURL:          getEnv("BASE_URL", ""),
		ListenAddr:       getEnv("LISTEN_ADDR", ":8080"),
		TLSCertFile:      getEnv("TLS_CERT_FILE", ""),
		TLSKeyFile:       getEnv("TLS_KEY_FILE", ""),
		JWTSigningKey:    jwtSigningKey,
		JWTEncryptionKey: jwtEncryptionKey,
		SessionTTL:       getEnvDuration("SESSION_TTL", 15*time.Minute),
		RefreshTokenTTL:  getEnvDuration("REFRESH_TOKEN_TTL", 7*24*time.Hour),
		AllowedOrigins:   getEnvStringSlice("ALLOWED_ORIGINS", []string{}),
		RateLimitRPS:     getEnvFloat("RATE_LIMIT_RPS", 10.0),
		RateLimitBurst:   getEnvInt("RATE_LIMIT_BURST", 20),
		EnforceHTTPS:     getEnvBool("ENFORCE_HTTPS", false),
		RotationWindow:   getEnvInt("ROTATION_WINDOW", 2),
	}

	if cfg.IssuerURL == "" || cfg.ClientID == "" || cfg.ClientSecret == "" {
		log.Fatal("OIDC_ISSUER_URL, OIDC_CLIENT_ID, and OIDC_CLIENT_SECRET are required")
	}

	if cfg.BaseURL == "" {
		log.Fatal("BASE_URL is required (e.g. https://kauth.example.com)")
	}

	// Get cluster API endpoint URL (must be set manually)
	clusterServer := getEnv("KUBERNETES_API_URL", "")
	if clusterServer == "" {
		log.Fatal("KUBERNETES_API_URL is required (e.g. https://kubernetes.example.com:6443)")
	}
	log.Printf("Cluster API URL: %s", clusterServer)

	// Auto-detect cluster CA (from env or in-cluster mount)
	clusterCA, err := server.GetClusterCA()
	if err != nil {
		log.Fatalf("Failed to get cluster CA: %v", err)
	}
	log.Printf("Cluster CA: loaded successfully")

	// Initialize JWT manager
	jwtManager, err := jwt.NewManager(cfg.JWTSigningKey, cfg.JWTEncryptionKey)
	if err != nil {
		log.Fatalf("Failed to initialize JWT manager: %v", err)
	}
	log.Printf("JWT manager initialized")

	ctx := context.Background()
	provider, err := oauth.NewProvider(ctx, oauth.Config{
		IssuerURL:    cfg.IssuerURL,
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.BaseURL + "/callback",
	})
	if err != nil {
		log.Fatalf("Failed to setup OIDC provider: %v", err)
	}

	loginHandler := handlers.NewLoginHandler(
		provider,
		jwtManager,
		cfg.ClusterName,
		clusterServer,
		clusterCA,
		cfg.SessionTTL,
		cfg.RefreshTokenTTL,
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
		w.Write([]byte("OK"))
	})

	// Apply middleware
	var handler http.Handler = mux

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

	log.Printf("Starting kauth server on %s", cfg.ListenAddr)
	log.Printf("Base URL: %s", cfg.BaseURL)
	log.Printf("Cluster: %s", cfg.ClusterName)
	log.Printf("Session TTL: %s", cfg.SessionTTL)
	log.Printf("Refresh Token TTL: %s", cfg.RefreshTokenTTL)
	log.Printf("Rate Limit: %.1f req/s, burst %d", cfg.RateLimitRPS, cfg.RateLimitBurst)
	if len(cfg.AllowedOrigins) > 0 {
		log.Printf("CORS Enabled for origins: %v", cfg.AllowedOrigins)
	}

	if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
		log.Printf("Starting with TLS")
		log.Fatal(http.ListenAndServeTLS(cfg.ListenAddr, cfg.TLSCertFile, cfg.TLSKeyFile, handler))
	} else {
		log.Printf("Starting without TLS (use TLS_CERT_FILE and TLS_KEY_FILE for HTTPS)")
		log.Fatal(http.ListenAndServe(cfg.ListenAddr, handler))
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
		log.Printf("Invalid duration for %s: %s, using default", key, value)
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
		log.Printf("Invalid int for %s: %s, using default", key, value)
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
		log.Printf("Invalid float for %s: %s, using default", key, value)
		return defaultValue
	}
	return floatVal
}

func getEnvBool(key string, defaultValue bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	boolVal, err := strconv.ParseBool(value)
	if err != nil {
		log.Printf("Invalid bool for %s: %s, using default", key, value)
		return defaultValue
	}
	return boolVal
}

func getEnvStringSlice(key string, defaultValue []string) []string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return strings.Split(value, ",")
}
