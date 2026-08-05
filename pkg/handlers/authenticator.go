package handlers

import (
	"context"
	"errors"
	"time"

	"kauth/pkg/jwt"
	"kauth/pkg/session"

	"golang.org/x/sync/singleflight"
)

const lastUsedThrottle = 30 * time.Second

var ErrUnauthorized = errors.New("unauthorized")
var ErrSessionStoreUnavailable = errors.New("session store unavailable")

type sessionStore interface {
	Get(ctx context.Context, sessionID string) (*session.Session, error)
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
		if errors.Is(err, session.ErrSessionNotFound) {
			return nil, ErrUnauthorized
		}
		return nil, ErrSessionStoreUnavailable
	}
	sess, ok := value.(*session.Session)
	if !ok || sess.Phase != session.PhaseActive || sess.Email == "" {
		return nil, ErrUnauthorized
	}

	// Avoid a second read on every API call when activity is already fresh.
	if sess.LastUsed.IsZero() || time.Since(sess.LastUsed) >= lastUsedThrottle {
		// Authentication remains successful if this best-effort update fails.
		_ = a.sessionClient.TouchLastUsed(ctx, credential.SessionID, lastUsedThrottle)
	}

	return &Identity{
		SessionID: credential.SessionID,
		Username:  sess.Email,
		Groups:    sess.Groups,
	}, nil
}
