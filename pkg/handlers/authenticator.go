package handlers

import (
	"context"
	"errors"
	"time"

	v1alpha1 "kauth/pkg/apis/kauth.io/v1alpha1"
	"kauth/pkg/jwt"
	"kauth/pkg/session"

	"golang.org/x/sync/singleflight"
)

const lastUsedThrottle = 30 * time.Second

var ErrUnauthorized = errors.New("unauthorized")

type sessionStore interface {
	Get(ctx context.Context, sessionID string) (*v1alpha1.OAuthSession, error)
	TouchLastUsed(ctx context.Context, sessionID string, window time.Duration) error
}

// Identity is the Kubernetes identity attached to an authenticated API request.
type Identity struct {
	SessionID string
	Username  string
	Groups    []string
}

// SessionAuthenticator validates API credentials against active OAuth sessions.
type SessionAuthenticator struct {
	jwtManager    *jwt.Manager
	sessionClient sessionStore
	lookups       singleflight.Group
}

func NewSessionAuthenticator(jwtManager *jwt.Manager, sessionClient *session.Client) *SessionAuthenticator {
	return &SessionAuthenticator{jwtManager: jwtManager, sessionClient: sessionClient}
}

func (a *SessionAuthenticator) Authenticate(ctx context.Context, rawToken string) (*Identity, error) {
	credential, err := a.jwtManager.ValidateAPIToken(rawToken)
	if err != nil {
		return nil, ErrUnauthorized
	}

	value, err, _ := a.lookups.Do(credential.SessionID, func() (any, error) {
		return a.sessionClient.Get(ctx, credential.SessionID)
	})
	if err != nil {
		return nil, ErrUnauthorized
	}
	oauthSession, ok := value.(*v1alpha1.OAuthSession)
	if !ok || oauthSession.Status.Phase != v1alpha1.SessionActive || oauthSession.Status.Email == "" {
		return nil, ErrUnauthorized
	}

	// Avoid a second CRD read on every API call when activity is already fresh.
	if oauthSession.Spec.LastUsed.IsZero() || time.Since(oauthSession.Spec.LastUsed.Time) >= lastUsedThrottle {
		// Authentication remains successful if this best-effort update fails.
		_ = a.sessionClient.TouchLastUsed(ctx, credential.SessionID, lastUsedThrottle)
	}

	return &Identity{
		SessionID: credential.SessionID,
		Username:  oauthSession.Status.Email,
		Groups:    oauthSession.Status.Groups,
	}, nil
}
