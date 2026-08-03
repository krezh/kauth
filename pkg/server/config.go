package server

import "time"

// Config holds the server configuration
type Config struct {
	// OIDC Configuration
	IssuerURL    string
	ClientID     string
	ClientSecret string

	// Kubernetes Configuration
	ClusterName string

	// Server Configuration
	BaseURL     string // e.g. https://kauth.example.com
	ListenAddr  string
	TLSCertFile string
	TLSKeyFile  string
	DatabaseURL string

	// JWT Configuration (required for stateless operation)
	JWTSigningKey     []byte        // 32+ bytes for HMAC-SHA256
	JWTEncryptionKey  []byte        // 32 bytes for AES-256
	SessionTTL        time.Duration // OAuth session TTL (default: 15 minutes)
	RefreshTokenTTL   time.Duration // Refresh token TTL (default: 7 days)
	SessionHistoryTTL time.Duration

	// Security Configuration
	AllowedOrigins    []string // CORS allowed origins (empty = none, ["*"] = all)
	RateLimitRPS      float64  // Rate limit requests per second (default: 10)
	RateLimitBurst    int      // Rate limit burst size (default: 20)
	TrustedProxyCIDRs []string // CIDR blocks for trusted reverse proxies (e.g., "10.0.0.0/8,172.16.0.0/12")
	AuditRetention    time.Duration
	AuditQueueSize    int

	// Authorization Configuration
	AllowedGroups []string // OIDC groups allowed to authenticate (empty = allow all)
	AdminGroups   []string // OIDC groups allowed to manage/revoke sessions (empty = no admins)
}
