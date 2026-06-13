package handlers

import (
	"context"
	"encoding/json"
	"log"
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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

	revoked := 0

	if req.SessionID != "" {
		if !admin {
			sess, err := h.sessionClient.Get(ctx, req.SessionID)
			if err != nil {
				log.Printf("REVOKE_FAILURE: session_id=%q error=%q", req.SessionID, err)
				http.Error(w, "Session not found", http.StatusNotFound)
				return
			}
			if !canRevokeSession(caller, admin, sess.Status.Email) {
				audit.Log(ctx, r, "session_revoke_denied",
					"session_id", req.SessionID,
					"caller", caller.Email,
					"owner", sess.Status.Email,
				)
				http.Error(w, "Forbidden: not your session", http.StatusForbidden)
				return
			}
		}

		if err := h.sessionClient.Revoke(ctx, req.SessionID); err != nil {
			log.Printf("REVOKE_FAILURE: session_id=%q error=%q", req.SessionID, err)
			http.Error(w, "Failed to revoke session", http.StatusInternalServerError)
			return
		}
		revoked = 1
		audit.Log(ctx, r, "session_revoked",
			"session_id", req.SessionID,
			"caller", caller.Email,
		)
		log.Printf("REVOKE_SUCCESS: session_id=%q by=%s", req.SessionID, caller.Email)
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

		sessions, err := h.sessionClient.GetByUser(ctx, req.UserEmail)
		if err != nil {
			log.Printf("REVOKE_FAILURE: user_email=%q error=%q", req.UserEmail, err)
			http.Error(w, "Failed to find user sessions", http.StatusInternalServerError)
			return
		}

		for _, s := range sessions {
			if s.Status.Phase == v1alpha1.SessionRevoked || s.Status.Phase == v1alpha1.SessionExpired {
				continue
			}
			if err := h.sessionClient.Revoke(ctx, s.Spec.State); err != nil {
				log.Printf("REVOKE_FAILURE: session_id=%q error=%q", s.Spec.State, err)
				continue
			}
			revoked++
		}

		audit.Log(ctx, r, "sessions_revoked",
			"user_email", req.UserEmail,
			"count", revoked,
			"caller", caller.Email,
		)
		log.Printf("REVOKE_SUCCESS: user_email=%q count=%d by=%s", req.UserEmail, revoked, caller.Email)
	}

	resp := RevokeResponse{Revoked: revoked}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func canRevokeSession(caller *CallerClaims, admin bool, ownerID string) bool {
	return admin || caller.Email == ownerID
}

func canRevokeUserSessions(caller *CallerClaims, admin bool, targetEmail string) bool {
	return admin || caller.Email == targetEmail
}
