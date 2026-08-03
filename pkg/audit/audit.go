package audit

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"kauth/pkg/middleware"
)

var ipExtractor *middleware.ClientIPExtractor
var requestStore struct {
	sync.RWMutex
	store   RequestStore
	cluster string
}

func SetIPExtractor(extractor *middleware.ClientIPExtractor) {
	ipExtractor = extractor
}

func SetRequestStore(store RequestStore, cluster string) {
	requestStore.Lock()
	defer requestStore.Unlock()
	requestStore.store = store
	requestStore.cluster = cluster
}

// Event types
const (
	EventLoginSuccess      = "login_success"
	EventLoginFailure      = "login_failure"
	EventRefreshSuccess    = "refresh_success"
	EventRefreshFailure    = "refresh_failure"
	EventAuthzAllow        = "authorization_allow"
	EventAuthzDeny         = "authorization_deny"
	EventKubernetesRequest = "kubernetes_request"
)

// Log logs an audit event with structured fields
func Log(ctx context.Context, r *http.Request, event string, attrs ...any) {
	// Get request ID from context
	requestID, _ := ctx.Value(middleware.RequestIDKey).(string)

	var remoteAddr string
	if ipExtractor != nil {
		remoteAddr = ipExtractor.GetClientIP(r)
	} else {
		remoteAddr = middleware.GetClientIP(r)
	}

	// Build base attributes
	baseAttrs := []any{
		"audit_event", event,
		"request_id", requestID,
		"remote_addr", remoteAddr,
		"user_agent", r.UserAgent(),
	}

	// Append additional attributes
	baseAttrs = append(baseAttrs, attrs...)

	// Log at info level for audit trail
	slog.InfoContext(ctx, "AUDIT", baseAttrs...)
}

// KubernetesRequest logs one completed request through the Kubernetes API proxy.
func KubernetesRequest(ctx context.Context, r *http.Request, sessionID, user string, groups []string, authenticated bool, status, responseBytes int, duration time.Duration) {
	Log(ctx, r, EventKubernetesRequest,
		"session_id", sessionID,
		"user", user,
		"groups", groups,
		"authenticated", authenticated,
		"method", r.Method,
		"path", r.URL.Path,
		"status", status,
		"response_bytes", responseBytes,
		"duration_ms", duration.Milliseconds(),
	)

	requestID, _ := ctx.Value(middleware.RequestIDKey).(string)
	remoteAddr := middleware.GetClientIP(r)
	if ipExtractor != nil {
		remoteAddr = ipExtractor.GetClientIP(r)
	}
	requestStore.RLock()
	store := requestStore.store
	cluster := requestStore.cluster
	requestStore.RUnlock()
	if store != nil {
		store.Record(RequestEvent{
			OccurredAt:    time.Now(),
			Cluster:       cluster,
			RequestID:     requestID,
			SessionID:     sessionID,
			Username:      user,
			Groups:        groups,
			Authenticated: authenticated,
			Method:        r.Method,
			Path:          r.URL.Path,
			StatusCode:    status,
			ResponseBytes: int64(responseBytes),
			Duration:      duration,
			RemoteAddr:    remoteAddr,
			UserAgent:     r.UserAgent(),
		})
	}
}

// LoginSuccess logs a successful login
func LoginSuccess(ctx context.Context, r *http.Request, email, cluster string, groups []string) {
	Log(ctx, r, EventLoginSuccess,
		"user", email,
		"cluster", cluster,
		"groups", groups,
	)
}

// LoginFailure logs a failed login
func LoginFailure(ctx context.Context, r *http.Request, reason string, email string) {
	Log(ctx, r, EventLoginFailure,
		"reason", reason,
		"user", email,
	)
}

// RefreshSuccess logs a successful token refresh
func RefreshSuccess(ctx context.Context, r *http.Request, email string) {
	Log(ctx, r, EventRefreshSuccess,
		"user", email,
	)
}

// RefreshFailure logs a failed token refresh
func RefreshFailure(ctx context.Context, r *http.Request, reason string, email string) {
	Log(ctx, r, EventRefreshFailure,
		"reason", reason,
		"user", email,
	)
}

// AuthorizationAllow logs a successful authorization check
func AuthorizationAllow(ctx context.Context, r *http.Request, email string, groups []string) {
	Log(ctx, r, EventAuthzAllow,
		"user", email,
		"groups", groups,
	)
}

// AuthorizationDeny logs a denied authorization check
func AuthorizationDeny(ctx context.Context, r *http.Request, email string, groups, allowedGroups []string) {
	Log(ctx, r, EventAuthzDeny,
		"user", email,
		"user_groups", groups,
		"allowed_groups", allowedGroups,
	)
}
