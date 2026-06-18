package handlers

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	v1alpha1 "kauth/pkg/apis/kauth.io/v1alpha1"
	"kauth/pkg/audit"
	"kauth/pkg/oauth"
	"kauth/pkg/session"

	authnv1 "k8s.io/api/authentication/v1"
)

// tokenPrefix marks a value as a kauth compound webhook credential of the form
// "kauth_<sessionID>.<oidcIDToken>". The sessionID is base64.RawURLEncoding and
// never contains a dot, so the first dot after the prefix is always the separator.
const tokenPrefix = "kauth_"

// webhookTimeout bounds how long a single TokenReview may take (OIDC verify +
// CRD lookups). The API server retries on failure, so failing closed is safe.
const webhookTimeout = 10 * time.Second

// sessionValidator is the subset of *session.Client the webhook needs. Defining
// it as an interface keeps HandleTokenReview unit-testable with a fake.
type sessionValidator interface {
	ValidateSession(ctx context.Context, sessionID string, expectedPhase v1alpha1.SessionPhase) error
	Get(ctx context.Context, sessionID string) (*v1alpha1.OAuthSession, error)
}

// WebhookHandler implements a Kubernetes token webhook authenticator. The API
// server POSTs a TokenReview here on every (uncached) token validation, letting
// kauth enforce per-session revocation that direct OIDC validation cannot.
type WebhookHandler struct {
	sessionClient sessionValidator
	// verifyToken verifies an OIDC ID token and returns its claims. It is a
	// field rather than an inline call so tests can inject a fake verifier
	// without standing up a real OIDC provider.
	verifyToken func(ctx context.Context, rawIDToken string) (*OIDCClaims, error)
}

// NewWebhookHandler builds a WebhookHandler. getProvider is a closure (not a
// captured *oauth.Provider) so the handler can be constructed before the OIDC
// provider finishes initializing; the route is gated by requireProvider anyway.
func NewWebhookHandler(getProvider func() *oauth.Provider, sessionClient *session.Client) *WebhookHandler {
	return &WebhookHandler{
		sessionClient: sessionClient,
		verifyToken: func(ctx context.Context, rawIDToken string) (*OIDCClaims, error) {
			provider := getProvider()
			if provider == nil {
				return nil, fmt.Errorf("OIDC provider not ready")
			}
			claims, _, err := VerifyAndExtractClaims(ctx, provider, rawIDToken)
			return claims, err
		},
	}
}

// HandleTokenReview processes a Kubernetes TokenReview request. It always
// responds HTTP 200 with a TokenReview body for authentication outcomes (both
// success and failure) as Kubernetes expects; only a malformed request itself
// yields a non-200 status.
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

	// Echo back the request's apiVersion/kind, defaulting to v1 if absent. This
	// transparently supports both authentication.k8s.io/v1 and v1beta1 clients.
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

// authenticate validates a compound token and returns the resolved username and
// groups on success. On failure it returns a short reason string (for audit and
// logging) and empty username/groups. The reason is intentionally not surfaced
// to the API server to avoid leaking detail to clients.
func (h *WebhookHandler) authenticate(ctx context.Context, rawToken string) (username string, groups []string, reason string) {
	if !strings.HasPrefix(rawToken, tokenPrefix) {
		return "", nil, "not a kauth compound token"
	}

	parts := strings.SplitN(strings.TrimPrefix(rawToken, tokenPrefix), ".", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", nil, "malformed compound token"
	}
	sessionID, rawIDToken := parts[0], parts[1]

	claims, err := h.verifyToken(ctx, rawIDToken)
	if err != nil {
		return "", nil, "ID token verification failed"
	}
	if claims.Email == "" {
		return "", nil, "ID token missing email claim"
	}

	if err := h.sessionClient.ValidateSession(ctx, sessionID, v1alpha1.SessionActive); err != nil {
		return "", nil, "session not active"
	}

	sess, err := h.sessionClient.Get(ctx, sessionID)
	if err != nil {
		return "", nil, "session lookup failed"
	}
	if sess.Status.Email != claims.Email {
		// Cross-validation: the session and the ID token must agree on identity,
		// so a sessionID from another user cannot be paired with this token.
		return "", nil, "session/token identity mismatch"
	}

	return claims.Email, claims.Groups, ""
}
