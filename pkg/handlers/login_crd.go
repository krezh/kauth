package handlers

import (
	"context"
	"log"
	"time"

	v1alpha1 "kauth/pkg/apis/kauth.io/v1alpha1"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
)

func (h *LoginHandler) watchSessions() {
	for {
		ctx := context.Background()
		watcher, err := h.sessionClient.Watch(ctx)
		if err != nil {
			log.Printf("Failed to start session watch: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}

		log.Println("Started watching OAuthSession CRDs")

		for event := range watcher.ResultChan() {
			if event.Type == watch.Modified || event.Type == watch.Added {
				unstructuredMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(event.Object)
				if err != nil {
					log.Printf("Failed to convert to unstructured: %v", err)
					continue
				}

				var session v1alpha1.OAuthSession
				err = runtime.DefaultUnstructuredConverter.FromUnstructured(unstructuredMap, &session)
				if err != nil {
					log.Printf("Failed to convert from unstructured: %v", err)
					continue
				}

				if session.Status.Phase == v1alpha1.SessionActive || session.Status.Error != "" {
					sessionID := session.Spec.SessionID

					h.sseMutex.Lock()
					listeners := h.sseListeners[sessionID]
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

						log.Printf("Notifying %d local listeners for session %s", len(listeners), sessionID[:8])

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

		log.Println("Session watch closed, restarting...")
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
			log.Printf("Failed to expire inactive sessions: %v", err)
		}

		err = h.sessionClient.CleanupOldSessions(ctx, 60*time.Second)
		if err != nil {
			log.Printf("Failed to cleanup old sessions: %v", err)
		}
	}
}
