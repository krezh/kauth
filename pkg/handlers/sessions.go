package handlers

import (
	"context"
	"net/http"
	"time"

	v1alpha1 "kauth/pkg/apis/kauth.io/v1alpha1"
	"kauth/pkg/session"
)

type SessionsHandler struct {
	sessionClient *session.Client
	adminGroups   []string
	sessionTTL    time.Duration
}

type SessionInfo struct {
	SessionID   string    `json:"sessionID"`
	UserID      string    `json:"user_id"`
	Email       string    `json:"email"`
	Username    string    `json:"username"`
	Phase       string    `json:"phase"`
	CreatedAt   time.Time `json:"created_at"`
	LastUsed    time.Time `json:"last_used"`
	RevokedAt   time.Time `json:"revoked_at,omitempty"`
	CompletedAt time.Time `json:"completed_at,omitempty"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"`
}

type SessionsResponse struct {
	Sessions []SessionInfo `json:"sessions"`
}

func NewSessionsHandler(sessionClient *session.Client, adminGroups []string, sessionTTL time.Duration) *SessionsHandler {
	return &SessionsHandler{
		sessionClient: sessionClient,
		adminGroups:   adminGroups,
		sessionTTL:    sessionTTL,
	}
}

func (h *SessionsHandler) HandleListSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	caller := getCaller(r.Context())
	if caller == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	admin := caller.isAdmin(h.adminGroups)

	// Non-admins can only see their own sessions.
	// Admins with no user_email filter list all active sessions via ListActive.
	var userEmail string
	if admin {
		userEmail = r.URL.Query().Get("user_email")
	} else {
		userEmail = caller.Email
	}

	var sessions []v1alpha1.OAuthSession
	var err error

	if userEmail != "" {
		sessions, err = h.sessionClient.GetByUser(ctx, userEmail)
	} else {
		sessions, err = h.sessionClient.ListActive(ctx)
	}

	if err != nil {
		http.Error(w, "Failed to list sessions", http.StatusInternalServerError)
		return
	}

	sessionInfos := make([]SessionInfo, 0, len(sessions))
	for _, s := range sessions {
		if s.Status.Phase != v1alpha1.SessionActive {
			continue
		}
		expiresAt := s.Spec.ExpiresAt.Time
		if s.Spec.ExpiresAt.IsZero() {
			expiresAt = s.Spec.CreatedAt.Add(h.sessionTTL)
			if !s.Spec.LastUsed.IsZero() {
				expiresAt = s.Spec.LastUsed.Add(h.sessionTTL)
			}
		}
		if expiresAt.IsZero() || !time.Now().Before(expiresAt) {
			continue
		}
		info := SessionInfo{
			SessionID: s.Spec.SessionID,
			UserID:    s.Spec.UserID,
			Email:     s.Status.Email,
			Username:  s.Status.Username,
			Phase:     string(s.Status.Phase),
			CreatedAt: s.Spec.CreatedAt.Time,
		}
		if !s.Spec.LastUsed.IsZero() {
			info.LastUsed = s.Spec.LastUsed.Time
		}
		info.ExpiresAt = expiresAt
		if s.Status.RevokedAt != nil {
			info.RevokedAt = s.Status.RevokedAt.Time
		}
		if s.Status.CompletedAt != nil {
			info.CompletedAt = s.Status.CompletedAt.Time
		}
		sessionInfos = append(sessionInfos, info)
	}

	writeJSON(w, SessionsResponse{Sessions: sessionInfos})
}
