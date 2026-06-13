package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	v1alpha1 "kauth/pkg/apis/kauth.io/v1alpha1"
	"kauth/pkg/session"
)

type SessionsHandler struct {
	sessionClient *session.Client
	adminGroups   []string
}

type SessionInfo struct {
	State       string    `json:"state"`
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

	// Non-admins can only see their own sessions
	userEmail := caller.Email
	if admin {
		if q := r.URL.Query().Get("user_email"); q != "" {
			userEmail = q
		}
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
		info := SessionInfo{
			State:     s.Spec.State,
			UserID:    s.Spec.UserID,
			Email:     s.Status.Email,
			Username:  s.Status.Username,
			Phase:     string(s.Status.Phase),
			CreatedAt: s.Spec.CreatedAt.Time,
		}
		if !s.Spec.LastUsed.IsZero() {
			info.LastUsed = s.Spec.LastUsed.Time
		}
		if s.Status.RevokedAt != nil {
			info.RevokedAt = s.Status.RevokedAt.Time
		}
		if s.Status.CompletedAt != nil {
			info.CompletedAt = s.Status.CompletedAt.Time
		}
		sessionInfos = append(sessionInfos, info)
	}

	resp := SessionsResponse{Sessions: sessionInfos}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
