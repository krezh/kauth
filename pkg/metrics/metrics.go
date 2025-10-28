package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// LoginAttempts tracks total login attempts by result
	LoginAttempts = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "kauth_login_attempts_total",
			Help: "Total number of login attempts by result (success/failure)",
		},
		[]string{"result", "reason"},
	)

	// LoginDuration tracks login flow duration
	LoginDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "kauth_login_duration_seconds",
			Help:    "Duration of login flow operations",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"operation"},
	)

	// TokenRefreshes tracks token refresh operations
	TokenRefreshes = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "kauth_token_refreshes_total",
			Help: "Total number of token refresh operations by result",
		},
		[]string{"result", "reason"},
	)

	// TokenRefreshDuration tracks token refresh duration
	TokenRefreshDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "kauth_token_refresh_duration_seconds",
			Help:    "Duration of token refresh operations",
			Buckets: prometheus.DefBuckets,
		},
	)

	// ActiveSessions tracks currently active OAuth sessions
	ActiveSessions = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "kauth_active_sessions",
			Help: "Number of active OAuth sessions (pending completion)",
		},
	)

	// CallbacksReceived tracks OAuth callbacks received
	CallbacksReceived = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "kauth_callbacks_received_total",
			Help: "Total number of OAuth callbacks received by result",
		},
		[]string{"result"},
	)

	// GroupAuthorizationChecks tracks group-based authorization checks
	GroupAuthorizationChecks = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "kauth_group_authorization_checks_total",
			Help: "Total number of group authorization checks by result",
		},
		[]string{"result"},
	)

	// HTTPRequestDuration tracks HTTP request duration by endpoint
	HTTPRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "kauth_http_request_duration_seconds",
			Help:    "Duration of HTTP requests by endpoint and status",
			Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
		},
		[]string{"endpoint", "method", "status"},
	)

	// HTTPRequestsInFlight tracks current in-flight HTTP requests
	HTTPRequestsInFlight = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "kauth_http_requests_in_flight",
			Help: "Number of HTTP requests currently being processed",
		},
	)

	// RateLimitHits tracks rate limit hits
	RateLimitHits = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "kauth_rate_limit_hits_total",
			Help: "Total number of requests that hit rate limits",
		},
	)

	// UniqueUsers tracks unique users by email (for active sessions)
	UniqueUsers = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kauth_unique_users",
			Help: "Number of unique users with active tokens (gauge per time window)",
		},
		[]string{"time_window"},
	)

	// OIDCProviderRequests tracks requests to the OIDC provider
	OIDCProviderRequests = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "kauth_oidc_provider_requests_total",
			Help: "Total number of requests to OIDC provider by operation and result",
		},
		[]string{"operation", "result"},
	)

	// OIDCProviderDuration tracks OIDC provider request duration
	OIDCProviderDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "kauth_oidc_provider_duration_seconds",
			Help:    "Duration of OIDC provider requests",
			Buckets: []float64{.1, .25, .5, 1, 2.5, 5, 10, 30},
		},
		[]string{"operation"},
	)

	// KubeconfigGenerations tracks kubeconfig generation operations
	KubeconfigGenerations = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "kauth_kubeconfig_generations_total",
			Help: "Total number of kubeconfig generation operations by result",
		},
		[]string{"result"},
	)
)

// RecordLoginSuccess records a successful login
func RecordLoginSuccess() {
	LoginAttempts.WithLabelValues("success", "").Inc()
}

// RecordLoginFailure records a failed login with reason
func RecordLoginFailure(reason string) {
	LoginAttempts.WithLabelValues("failure", reason).Inc()
}

// RecordTokenRefreshSuccess records a successful token refresh
func RecordTokenRefreshSuccess() {
	TokenRefreshes.WithLabelValues("success", "").Inc()
}

// RecordTokenRefreshFailure records a failed token refresh with reason
func RecordTokenRefreshFailure(reason string) {
	TokenRefreshes.WithLabelValues("failure", reason).Inc()
}

// RecordCallbackSuccess records a successful OAuth callback
func RecordCallbackSuccess() {
	CallbacksReceived.WithLabelValues("success").Inc()
}

// RecordCallbackFailure records a failed OAuth callback
func RecordCallbackFailure() {
	CallbacksReceived.WithLabelValues("failure").Inc()
}

// RecordGroupAuthorizationSuccess records a successful group authorization check
func RecordGroupAuthorizationSuccess() {
	GroupAuthorizationChecks.WithLabelValues("allowed").Inc()
}

// RecordGroupAuthorizationFailure records a failed group authorization check
func RecordGroupAuthorizationFailure() {
	GroupAuthorizationChecks.WithLabelValues("denied").Inc()
}

// RecordKubeconfigGenerationSuccess records a successful kubeconfig generation
func RecordKubeconfigGenerationSuccess() {
	KubeconfigGenerations.WithLabelValues("success").Inc()
}

// RecordKubeconfigGenerationFailure records a failed kubeconfig generation
func RecordKubeconfigGenerationFailure() {
	KubeconfigGenerations.WithLabelValues("failure").Inc()
}

// RecordOIDCRequest records an OIDC provider request
func RecordOIDCRequest(operation, result string) {
	OIDCProviderRequests.WithLabelValues(operation, result).Inc()
}
