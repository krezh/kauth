package oauth

import (
	"kauth/pkg/metrics"
	"net/http"
	"strconv"
)

// metricsRoundTripper wraps an HTTP RoundTripper to capture status codes for metrics
type metricsRoundTripper struct {
	next      http.RoundTripper
	operation string
}

// RoundTrip executes the HTTP request and records metrics
func (m *metricsRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := m.next.RoundTrip(req)

	if err != nil {
		// Network error or other non-HTTP error
		metrics.RecordOIDCError(m.operation, "network_error")
		return resp, err
	}

	// Record status code if request succeeded at HTTP level
	if resp.StatusCode >= 400 {
		metrics.RecordOIDCError(m.operation, strconv.Itoa(resp.StatusCode))
	}

	return resp, err
}

// NewMetricsHTTPClient creates an HTTP client that records OIDC provider metrics
func NewMetricsHTTPClient(operation string) *http.Client {
	return &http.Client{
		Transport: &metricsRoundTripper{
			next:      http.DefaultTransport,
			operation: operation,
		},
	}
}
