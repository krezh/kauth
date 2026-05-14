package oauth

import (
	"net/http"
)

// NewMetricsHTTPClient creates an HTTP client for OIDC provider requests
func NewMetricsHTTPClient(_ string) *http.Client {
	return &http.Client{
		Transport: http.DefaultTransport,
	}
}
