package handlers

import (
	"context"
	"log/slog"
	"time"

	v1alpha1 "kauth/pkg/apis/kauth.io/v1alpha1"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
)

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
			slog.Debug("Session watch restarted", "resourceVersion", resourceVersion)
		}

		for event := range watcher.ResultChan() {
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
							Error:        session.Status.Error,
						}

						slog.Info("Notifying local listeners for session", "session", sessionID[:8], "count", len(listeners))

						for _, listener := range listeners {
							select {
							case listener <- status:
							default:
							}
						}
					}
				}
			}
		}

		slog.Debug("Session watch closed, restarting...")
		time.Sleep(5 * time.Second)
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

		err = h.sessionClient.CleanupOldSessions(ctx, 60*time.Second)
		if err != nil {
			slog.Error("Failed to cleanup old sessions", "error", err)
		}
	}
}
