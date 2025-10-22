package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"kauth/pkg/handlers"
	"kauth/pkg/oauth"
	"kauth/pkg/server"
)

func main() {
	cfg := server.Config{
		IssuerURL:    getEnv("OIDC_ISSUER_URL", ""),
		ClientID:     getEnv("OIDC_CLIENT_ID", ""),
		ClientSecret: getEnv("OIDC_CLIENT_SECRET", ""),
		ClusterName:  getEnv("CLUSTER_NAME", "kubernetes"),
		BaseURL:      getEnv("BASE_URL", ""),
		ListenAddr:   getEnv("LISTEN_ADDR", ":8080"),
		TLSCertFile:  getEnv("TLS_CERT_FILE", ""),
		TLSKeyFile:   getEnv("TLS_KEY_FILE", ""),
	}

	if cfg.IssuerURL == "" || cfg.ClientID == "" || cfg.ClientSecret == "" {
		log.Fatal("OIDC_ISSUER_URL, OIDC_CLIENT_ID, and OIDC_CLIENT_SECRET are required")
	}

	if cfg.BaseURL == "" {
		log.Fatal("BASE_URL is required (e.g. https://kauth.example.com)")
	}

	// Auto-detect cluster server (from in-cluster env vars or default)
	clusterServer := server.GetClusterServer()
	log.Printf("Cluster server: %s", clusterServer)

	// Auto-detect cluster CA (from env or in-cluster mount)
	clusterCA, err := server.GetClusterCA()
	if err != nil {
		log.Fatalf("Failed to get cluster CA: %v", err)
	}
	log.Printf("Cluster CA: loaded successfully")

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

	loginHandler := handlers.NewLoginHandler(provider, cfg.ClusterName, clusterServer, clusterCA)

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
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	log.Printf("Starting kauth server on %s", cfg.ListenAddr)
	log.Printf("Base URL: %s", cfg.BaseURL)
	log.Printf("Cluster: %s", cfg.ClusterName)

	if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
		log.Fatal(http.ListenAndServeTLS(cfg.ListenAddr, cfg.TLSCertFile, cfg.TLSKeyFile, mux))
	} else {
		log.Fatal(http.ListenAndServe(cfg.ListenAddr, mux))
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
