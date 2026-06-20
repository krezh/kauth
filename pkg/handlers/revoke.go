package handlers

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	v1alpha1 "kauth/pkg/apis/kauth.io/v1alpha1"
	"kauth/pkg/audit"
	"kauth/pkg/session"
)

type RevokeHandler struct {
	sessionClient *session.Client
	adminGroups   []string
}

type RevokeRequest struct {
	SessionID string `json:"session_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`
}

type RevokeResponse struct {
	Revoked int `json:"revoked"`
}

func NewRevokeHandler(sessionClient *session.Client, adminGroups []string) *RevokeHandler {
	return &RevokeHandler{
		sessionClient: sessionClient,
		adminGroups:   adminGroups,
	}
}

func (h *RevokeHandler) HandleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	caller := getCaller(r.Context())
	if caller == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req RevokeRequest
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.SessionID == "" && req.UserEmail == "" {
		http.Error(w, "Either session_id or user_email is required", http.StatusBadRequest)
		return
	}

	admin := caller.isAdmin(h.adminGroups)

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	// Validate all authorization upfront before any mutations so that a
	// forbidden user_email check cannot silently succeed after session_id was
	// already revoked.
	var singleSess *v1alpha1.OAuthSession
	if req.SessionID != "" {
		s, err := h.sessionClient.Get(ctx, req.SessionID)
		if err != nil {
			slog.WarnContext(ctx, "revoke: session not found", "session_id", req.SessionID, "error", err)
			http.Error(w, "Session not found", http.StatusNotFound)
			return
		}
		singleSess = s
		if !canRevokeSession(caller, admin, singleSess.Status.Email) {
			audit.Log(ctx, r, "session_revoke_denied",
				"session_id", req.SessionID,
				"caller", caller.Email,
				"owner", singleSess.Status.Email,
			)
			http.Error(w, "Forbidden: not your session", http.StatusForbidden)
			return
		}
	}
	if req.UserEmail != "" {
		if !canRevokeUserSessions(caller, admin, req.UserEmail) {
			audit.Log(ctx, r, "sessions_revoke_denied",
				"target_user", req.UserEmail,
				"caller", caller.Email,
			)
			http.Error(w, "Forbidden: admin access required", http.StatusForbidden)
			return
		}
	}

	revoked := 0

	if singleSess != nil {
		if err := h.sessionClient.Revoke(ctx, req.SessionID); err != nil {
			slog.ErrorContext(ctx, "revoke: failed to revoke session", "session_id", req.SessionID, "error", err)
			http.Error(w, "Failed to revoke session", http.StatusInternalServerError)
			return
		}
		revoked = 1
		audit.Log(ctx, r, "session_revoked",
			"session_id", req.SessionID,
			"owner", singleSess.Status.Email,
			"caller", caller.Email,
		)
		slog.InfoContext(ctx, "revoke: session revoked", "session_id", req.SessionID, "owner", singleSess.Status.Email, "by", caller.Email)
	}

	if req.UserEmail != "" {

		sessions, err := h.sessionClient.GetByUser(ctx, req.UserEmail)
		if err != nil {
			slog.ErrorContext(ctx, "revoke: failed to list user sessions", "user_email", req.UserEmail, "error", err)
			http.Error(w, "Failed to find user sessions", http.StatusInternalServerError)
			return
		}

		for _, s := range sessions {
			if s.Status.Phase == v1alpha1.SessionRevoked || s.Status.Phase == v1alpha1.SessionExpired {
				continue
			}
			if s.Spec.SessionID == req.SessionID {
				continue // already revoked in the session_id block above
			}
			if err := h.sessionClient.Revoke(ctx, s.Spec.SessionID); err != nil {
				slog.WarnContext(ctx, "revoke: failed to revoke session", "session_id", s.Spec.SessionID, "error", err)
				continue
			}
			revoked++
		}

		audit.Log(ctx, r, "sessions_revoked",
			"user_email", req.UserEmail,
			"count", revoked,
			"caller", caller.Email,
		)
		slog.InfoContext(ctx, "revoke: user sessions revoked", "user_email", req.UserEmail, "count", revoked, "by", caller.Email)
	}

	writeJSON(w, RevokeResponse{Revoked: revoked})
}

func canRevokeSession(caller *CallerClaims, admin bool, ownerID string) bool {
	return admin || caller.Email == ownerID
}

func canRevokeUserSessions(caller *CallerClaims, admin bool, targetEmail string) bool {
	return admin || caller.Email == targetEmail
}
