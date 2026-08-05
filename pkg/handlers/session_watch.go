package handlers

import (
	"context"
	"log/slog"
	"time"

	"kauth/pkg/session"
)

// notifyWorkers bounds the concurrent per-event session reads started by watchSessions.
const notifyWorkers = 8

// watchSessions fans out Active/errored sessions to local SSE listeners. Notifications are
// handed to a bounded worker pool so a slow session read cannot stall the subscription and
// make the hub drop a login completion.
func (h *LoginHandler) watchSessions() {
	ch, unsubscribe := h.sessionClient.Subscribe()
	defer unsubscribe()
	slog.Info("Started watching session events")

	work := make(chan string, notifyWorkers)
	defer close(work)
	for range notifyWorkers {
		go func() {
			for sessionID := range work {
				h.notifyListeners(sessionID)
			}
		}()
	}

	for ev := range ch {
		select {
		case work <- ev.SessionID:
		default:
			// every worker is busy; handle it here rather than dropping the event
			h.notifyListeners(ev.SessionID)
		}
	}
}

// notifyListeners re-reads the session and pushes a StatusResponse to its local listeners.
func (h *LoginHandler) notifyListeners(sessionID string) {
	h.sseMutex.Lock()
	src := h.sseListeners[sessionID]
	listeners := make([]chan StatusResponse, len(src))
	copy(listeners, src)
	h.sseMutex.Unlock()

	if len(listeners) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sess, err := h.sessionClient.Get(ctx, sessionID)
	if err != nil {
		slog.Error("session watch: failed to fetch session for notification", "session", sessionID[:min(8, len(sessionID))], "error", err)
		return
	}
	if sess.Phase != session.PhaseActive && sess.Error == "" {
		return
	}

	var kubeconfig string
	if sess.Phase == session.PhaseActive && sess.Email != "" {
		kubeconfig = h.kubeconfigGen.Generate(sess.Email, sess.Username)
	}
	status := StatusResponse{
		Ready:        sess.Phase == session.PhaseActive,
		Kubeconfig:   kubeconfig,
		RefreshToken: sess.RefreshToken,
		SessionID:    sess.SessionID,
		APIToken:     sess.APIToken,
		Error:        sess.Error,
	}
	if sess.APIToken != "" {
		if apiCredential, err := h.jwtManager.DecodeAPIToken(sess.APIToken); err == nil {
			status.SessionExpiry = apiCredential.ExpiresAt
		}
	}

	slog.Info("Notifying local listeners for session", "session", sessionID[:min(8, len(sessionID))], "count", len(listeners))
	for _, listener := range listeners {
		select {
		case listener <- status:
		default:
		}
	}
}

func (h *LoginHandler) cleanupSessions() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		ctx := context.Background()

		if err := h.sessionClient.ExpireInactiveSessions(ctx, h.refreshTokenTTL); err != nil {
			slog.Error("Failed to expire inactive sessions", "error", err)
		}

		if err := h.sessionClient.CleanupOldSessions(ctx, h.sessionHistoryTTL, h.sessionTTL); err != nil {
			slog.Error("Failed to cleanup old sessions", "error", err)
		}
	}
}
