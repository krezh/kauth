package server

import (
	"fmt"
	"os"
)

const (
	// Default Kubernetes service DNS name
	defaultKubernetesService = "https://kubernetes.default.svc"
	
	// Environment variables that may contain the API server URL
	kubernetesServiceHostEnv = "KUBERNETES_SERVICE_HOST"
	kubernetesServicePortEnv = "KUBERNETES_SERVICE_PORT"
)

// GetClusterServer returns the Kubernetes API server URL
// It will try in this order:
// 1. CLUSTER_SERVER environment variable
// 2. Build from KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT (in-cluster)
// 3. Default to https://kubernetes.default.svc
func GetClusterServer() string {
	// Try explicit configuration
	if server := os.Getenv("CLUSTER_SERVER"); server != "" {
		return server
	}

	// Try in-cluster environment variables
	host := os.Getenv(kubernetesServiceHostEnv)
	port := os.Getenv(kubernetesServicePortEnv)
	
	if host != "" && port != "" {
		return fmt.Sprintf("https://%s:%s", host, port)
	}

	// Default to kubernetes service DNS
	return defaultKubernetesService
}
