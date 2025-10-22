package server

import (
	"encoding/base64"
	"fmt"
	"os"
)

const (
	// Default path to cluster CA when running in-cluster
	inClusterCAPath = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

// GetClusterCA returns the base64-encoded cluster CA certificate
// It will try in this order:
// 1. CLUSTER_CA_DATA environment variable (base64 encoded)
// 2. CLUSTER_CA_FILE environment variable (path to file)
// 3. In-cluster CA at /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
func GetClusterCA() (string, error) {
	// Try CLUSTER_CA_DATA first (already base64 encoded)
	if caData := os.Getenv("CLUSTER_CA_DATA"); caData != "" {
		return caData, nil
	}

	// Try CLUSTER_CA_FILE (path to PEM file)
	if caFile := os.Getenv("CLUSTER_CA_FILE"); caFile != "" {
		data, err := os.ReadFile(caFile)
		if err != nil {
			return "", fmt.Errorf("failed to read CA file %s: %w", caFile, err)
		}
		return base64.StdEncoding.EncodeToString(data), nil
	}

	// Try in-cluster CA
	if data, err := os.ReadFile(inClusterCAPath); err == nil {
		return base64.StdEncoding.EncodeToString(data), nil
	}

	return "", fmt.Errorf("no cluster CA found - set CLUSTER_CA_DATA or CLUSTER_CA_FILE, or run in-cluster")
}
