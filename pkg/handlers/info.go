package handlers

import (
	"encoding/json"
	"net/http"
)

// InfoResponse contains cluster and auth configuration
type InfoResponse struct {
	ClusterName   string `json:"cluster_name"`
	ClusterServer string `json:"cluster_server"`
	IssuerURL     string `json:"issuer_url"`
	ClientID      string `json:"client_id"`
	LoginURL      string `json:"login_url"`
	RefreshURL    string `json:"refresh_url"` // New: endpoint for token refresh
}

// HandleInfo returns cluster configuration
func HandleInfo(clusterName, clusterServer, issuerURL, clientID, baseURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		info := InfoResponse{
			ClusterName:   clusterName,
			ClusterServer: clusterServer,
			IssuerURL:     issuerURL,
			ClientID:      clientID,
			LoginURL:      baseURL + "/login",
			RefreshURL:    baseURL + "/refresh",
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(info)
	}
}
