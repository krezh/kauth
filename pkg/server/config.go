package server

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
	BaseURL      string // e.g. https://kauth.example.com
	ListenAddr   string
	TLSCertFile  string
	TLSKeyFile   string
}
