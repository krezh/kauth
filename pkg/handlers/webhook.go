package handlers

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	v1alpha1 "kauth/pkg/apis/kauth.io/v1alpha1"
	"kauth/pkg/audit"
	"kauth/pkg/jwt"
	"kauth/pkg/session"

	authnv1 "k8s.io/api/authentication/v1"
)

// webhookTimeout bounds how long a single TokenReview may take (decrypt + CRD lookup).
const webhookTimeout = 10 * time.Second

// lastUsedThrottle bounds how often the webhook bumps .spec.lastUsed per session.
// The API server may fire many uncached TokenReviews within seconds (different
// verbs, users, cache evictions); writing on every one would hammer etcd and
// conflict with concurrent refresh/revoke writes. 30s is "live enough" for the
// kubectl Last Used column (which renders as a relative age recomputed at print
// time) while keeping the write rate to at most a couple per minute per session.
const lastUsedThrottle = 30 * time.Second

// sessionStore is the subset of *session.Client the webhook needs: read the
// session CRD to authenticate, and bump LastUsed on a successful validation so
// the expiry goroutine and the kubectl Last Used column reflect genuine usage.
type sessionStore interface {
	Get(ctx context.Context, sessionID string) (*v1alpha1.OAuthSession, error)
	TouchLastUsed(ctx context.Context, sessionID string, window time.Duration) error
}

// WebhookHandler implements a Kubernetes token webhook authenticator. The API
// server POSTs a TokenReview here on every (uncached) token validation. The
// token is an encrypted session credential; the webhook decrypts it, looks up
// the session CRD, and returns the user's email and groups from the CRD status.
// No OIDC verification occurs here — the CRD is the authoritative source of truth.
type WebhookHandler struct {
	jwtManager    *jwt.Manager
	sessionClient sessionStore
}

// NewWebhookHandler builds a WebhookHandler.
func NewWebhookHandler(jwtManager *jwt.Manager, sessionClient *session.Client) *WebhookHandler {
	return &WebhookHandler{
		jwtManager:    jwtManager,
		sessionClient: sessionClient,
	}
}

// HandleTokenReview processes a Kubernetes TokenReview request. It always
// responds HTTP 200 with a TokenReview body for authentication outcomes; only
// a malformed request itself yields a non-200 status.
func (h *WebhookHandler) HandleTokenReview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req authnv1.TokenReview
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	apiVersion := req.APIVersion
	if apiVersion == "" {
		apiVersion = "authentication.k8s.io/v1"
	}
	kind := req.Kind
	if kind == "" {
		kind = "TokenReview"
	}

	ctx, cancel := context.WithTimeout(r.Context(), webhookTimeout)
	defer cancel()

	username, groups, reason := h.authenticate(ctx, req.Spec.Token)
	authenticated := reason == ""

	resp := authnv1.TokenReview{}
	resp.APIVersion = apiVersion
	resp.Kind = kind
	resp.Status.Authenticated = authenticated
	if authenticated {
		resp.Status.User = authnv1.UserInfo{
			Username: username,
			Groups:   groups,
		}
		audit.Log(ctx, r, "webhook_token_review", "result", "authenticated", "user", username)
	} else {
		audit.Log(ctx, r, "webhook_token_review", "result", "denied", "reason", reason)
		slog.WarnContext(ctx, "webhook token review denied", "reason", reason)
	}

	w.WriteHeader(http.StatusOK)
	writeJSON(w, resp)
}

// authenticate decrypts the webhook token, looks up the session CRD, and
// returns the user's email and groups on success. On failure it returns a
// short reason string (for audit/logging only; not surfaced to the API server).
func (h *WebhookHandler) authenticate(ctx context.Context, rawToken string) (username string, groups []string, reason string) {
	cred, err := h.jwtManager.ValidateWebhookToken(rawToken)
	if err != nil {
		return "", nil, "invalid webhook token"
	}

	sess, err := h.sessionClient.Get(ctx, cred.SessionID)
	if err != nil {
		return "", nil, "session lookup failed"
	}

	if sess.Status.Phase != v1alpha1.SessionActive {
		return "", nil, "session not active"
	}

	// Bump LastUsed so the expiry goroutine sees fresh activity and the
	// kubectl Last Used column advances. Throttled per-session; best-effort —
	// a write failure must not fail the auth decision.
	_ = h.sessionClient.TouchLastUsed(ctx, cred.SessionID, lastUsedThrottle)

	return sess.Status.Email, sess.Status.Groups, ""
}
