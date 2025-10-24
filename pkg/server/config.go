package server

import "time"

// Config holds the server configuration
type Config struct {
	// OIDC Configuration
	IssuerURL    string
	ClientID     string
	ClientSecret string

	// Kubernetes Configuration
	ClusterName   string
	ClusterServer string
	ClusterCA     string // Base64 encoded CA cert

	// Server Configuration
	BaseURL     string // e.g. https://kauth.example.com
	ListenAddr  string
	TLSCertFile string
	TLSKeyFile  string

	// JWT Configuration (required for stateless operation)
	JWTSigningKey    []byte        // 32+ bytes for HMAC-SHA256
	JWTEncryptionKey []byte        // 32 bytes for AES-256
	SessionTTL       time.Duration // OAuth session TTL (default: 15 minutes)
	RefreshTokenTTL  time.Duration // Refresh token TTL (default: 7 days)

	// Security Configuration
	AllowedOrigins []string // CORS allowed origins (empty = none, ["*"] = all)
	RateLimitRPS   float64  // Rate limit requests per second (default: 10)
	RateLimitBurst int      // Rate limit burst size (default: 20)
	RotationWindow int      // Number of previous refresh tokens to accept (default: 2)

	// Authorization Configuration
	AllowedGroups []string // OIDC groups allowed to authenticate (empty = allow all)
}
