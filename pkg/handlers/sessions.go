package handlers

import (
	"context"
	"net/http"
	"time"

	"kauth/pkg/session"
)

type SessionsHandler struct {
	sessionClient *session.Client
	adminGroups   []string
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
}

type SessionsResponse struct {
	Sessions []SessionInfo `json:"sessions"`
}

func NewSessionsHandler(sessionClient *session.Client, adminGroups []string) *SessionsHandler {
	return &SessionsHandler{
		sessionClient: sessionClient,
		adminGroups:   adminGroups,
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

	var sessions []session.Session
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
		info := SessionInfo{
			SessionID: s.SessionID,
			UserID:    s.UserID,
			Email:     s.Email,
			Username:  s.Username,
			Phase:     string(s.Phase),
			CreatedAt: s.CreatedAt,
		}
		if !s.LastUsed.IsZero() {
			info.LastUsed = s.LastUsed
		}
		if s.RevokedAt != nil {
			info.RevokedAt = *s.RevokedAt
		}
		if s.CompletedAt != nil {
			info.CompletedAt = *s.CompletedAt
		}
		sessionInfos = append(sessionInfos, info)
	}

	writeJSON(w, SessionsResponse{Sessions: sessionInfos})
}
