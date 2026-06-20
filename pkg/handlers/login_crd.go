package handlers

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	v1alpha1 "kauth/pkg/apis/kauth.io/v1alpha1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
)

// watchIdleTimeout is how long to wait without any event (including bookmarks)
// before treating the stream as stalled and reconnecting. VPN middleboxes can
// half-close the TCP socket without EOF, so the range loop would block forever
// without this safety net. Bookmarks arrive at most every ~60 s on a healthy
// stream; 90 s gives enough headroom to avoid false positives.
const watchIdleTimeout = 90 * time.Second

func (h *LoginHandler) watchSessions() {
	var resourceVersion string
	first := true

	for {
		ctx := context.Background()
		watcher, err := h.sessionClient.Watch(ctx, resourceVersion)
		if err != nil {
			slog.Error("Failed to start session watch", "error", err)
			time.Sleep(5 * time.Second)
			continue
		}

		if first {
			slog.Info("Started watching OAuthSession CRDs")
			first = false
		} else {
			slog.Info("Session watch restarted", "resourceVersion", resourceVersion)
		}

		idleTimer := time.NewTimer(watchIdleTimeout)
	eventLoop:
		for {
			select {
			case event, ok := <-watcher.ResultChan():
				if !ok {
					break eventLoop
				}
				if !idleTimer.Stop() {
					select {
					case <-idleTimer.C:
					default:
					}
				}
				idleTimer.Reset(watchIdleTimeout)

				if event.Type == watch.Error {
					if status, ok := event.Object.(*metav1.Status); ok {
						slog.Error("Session watch error", "code", status.Code, "message", status.Message)
						if status.Code == http.StatusGone {
							resourceVersion = ""
						}
					} else {
						slog.Error("Session watch error", "event", event.Object)
					}
					watcher.Stop()
					break eventLoop
				}

				if event.Type == watch.Bookmark {
					if obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(event.Object); err == nil {
						if rv, ok := obj["metadata"].(map[string]any)["resourceVersion"].(string); ok && rv != "" {
							resourceVersion = rv
						}
					}
					continue
				}

				if event.Type == watch.Modified || event.Type == watch.Added {
					unstructuredMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(event.Object)
					if err != nil {
						slog.Error("Failed to convert session to unstructured", "error", err)
						continue
					}

					if rv, ok := unstructuredMap["metadata"].(map[string]any)["resourceVersion"].(string); ok && rv != "" {
						resourceVersion = rv
					}

					var session v1alpha1.OAuthSession
					if err = runtime.DefaultUnstructuredConverter.FromUnstructured(unstructuredMap, &session); err != nil {
						slog.Error("Failed to convert session from unstructured", "error", err)
						continue
					}

					if session.Status.Phase == v1alpha1.SessionActive || session.Status.Error != "" {
						sessionID := session.Spec.SessionID

						h.sseMutex.Lock()
						src := h.sseListeners[sessionID]
						listeners := make([]chan StatusResponse, len(src))
						copy(listeners, src)
						h.sseMutex.Unlock()

						slog.Info("Session went Active, checking for local listeners", "session", sessionID[:min(8, len(sessionID))], "listeners", len(listeners))

						if len(listeners) > 0 {
							var kubeconfig string
							if session.Status.Phase == v1alpha1.SessionActive && session.Status.Email != "" {
								kubeconfig = h.kubeconfigGen.Generate(session.Status.Email, session.Status.Username)
							}

							status := StatusResponse{
								Ready:        session.Status.Phase == v1alpha1.SessionActive,
								Kubeconfig:   kubeconfig,
								RefreshToken: session.Status.RefreshToken,
								SessionID:    session.Spec.SessionID,
								WebhookToken: session.Status.WebhookToken,
								Error:        session.Status.Error,
							}
							if session.Status.WebhookToken != "" {
								if wt, err := h.jwtManager.DecodeWebhookToken(session.Status.WebhookToken); err == nil {
									status.SessionExpiry = wt.ExpiresAt
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
					}
				}

			case <-idleTimer.C:
				slog.Debug("Session watch idle, reconnecting")
				watcher.Stop()
				break eventLoop
			}
		}
		idleTimer.Stop()

		slog.Debug("Session watch closed, restarting...")
		time.Sleep(1 * time.Second)
	}
}

func (h *LoginHandler) cleanupSessions() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		ctx := context.Background()

		err := h.sessionClient.ExpireInactiveSessions(ctx, h.refreshTokenTTL)
		if err != nil {
			slog.Error("Failed to expire inactive sessions", "error", err)
		}

		err = h.sessionClient.CleanupOldSessions(ctx, h.sessionTTL)
		if err != nil {
			slog.Error("Failed to cleanup old sessions", "error", err)
		}
	}
}
