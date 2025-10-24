package handlers

import (
	"context"
	"log"
	"time"

	v1alpha1 "kauth/pkg/apis/kauth.io/v1alpha1"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
)

// watchSessions watches for OAuthSession CRD updates and notifies local SSE listeners
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
				// Convert unstructured to OAuthSession
				unstructuredObj, ok := event.Object.(runtime.Object)
				if !ok {
					continue
				}

				// Try to convert to our type
				unstructuredMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(unstructuredObj)
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

				// Only notify if status is ready or has error
				if session.Status.Ready || session.Status.Error != "" {
					state := session.Spec.State

					h.sseMutex.Lock()
					listeners := h.sseListeners[state]
					h.sseMutex.Unlock()

					if len(listeners) > 0 {
						status := StatusResponse{
							Ready:        session.Status.Ready,
							Kubeconfig:   session.Status.Kubeconfig,
							RefreshToken: session.Status.RefreshToken,
							Error:        session.Status.Error,
						}

						log.Printf("Notifying %d local listeners for state %s", len(listeners), state[:8])

						// Notify all local listeners
						for _, listener := range listeners {
							select {
							case listener <- status:
							default:
								// Listener channel full, skip
							}
						}
					}
				}
			}
		}

		// Watch closed, restart after delay
		log.Println("Session watch closed, restarting...")
		time.Sleep(5 * time.Second)
	}
}

// cleanupSessions periodically cleans up old OAuthSession CRDs
func (h *LoginHandler) cleanupSessions() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		ctx := context.Background()
		err := h.sessionClient.CleanupOldSessions(ctx, 60*time.Second)
		if err != nil {
			log.Printf("Failed to cleanup old sessions: %v", err)
		}
	}
}
