package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"slices"
	"sync"
	"time"

	v1alpha1 "kauth/pkg/apis/kauth.io/v1alpha1"
	"kauth/pkg/jwt"
	"kauth/pkg/oauth"
	"kauth/pkg/session"

	"golang.org/x/oauth2"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	c "maragu.dev/gomponents"
	hh "maragu.dev/gomponents/html"
)

type LoginHandler struct {
	provider        *oauth.Provider
	jwtManager      *jwt.Manager
	clusterName     string
	clusterServer   string
	clusterCA       string
	sessionTTL      time.Duration
	refreshTokenTTL time.Duration
	allowedGroups   []string

	// CRD client for distributed session storage
	sessionClient *session.Client

	// Local SSE listeners (in-memory, per-pod)
	sseListeners map[string][]chan StatusResponse
	sseMutex     sync.RWMutex
}

type StartLoginResponse struct {
	SessionToken string `json:"session_token"` // JWT containing state & verifier
	LoginURL     string `json:"login_url"`
}

type StatusResponse struct {
	Ready        bool   `json:"ready"`
	Kubeconfig   string `json:"kubeconfig,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Error        string `json:"error,omitempty"`
}

func NewLoginHandler(
	provider *oauth.Provider,
	jwtManager *jwt.Manager,
	clusterName, clusterServer, clusterCA string,
	sessionTTL, refreshTokenTTL time.Duration,
	allowedGroups []string,
	sessionClient *session.Client,
) *LoginHandler {
	h := &LoginHandler{
		provider:        provider,
		jwtManager:      jwtManager,
		clusterName:     clusterName,
		clusterServer:   clusterServer,
		clusterCA:       clusterCA,
		sessionTTL:      sessionTTL,
		refreshTokenTTL: refreshTokenTTL,
		allowedGroups:   allowedGroups,
		sessionClient:   sessionClient,
		sseListeners:    make(map[string][]chan StatusResponse),
	}

	// Start watching for session updates from CRD
	go h.watchSessions()

	// Cleanup old sessions periodically (30 second TTL)
	go h.cleanupSessions()

	return h
}

func (h *LoginHandler) HandleStartLogin(w http.ResponseWriter, r *http.Request) {
	// Generate state and PKCE verifier
	state := generateRandomString(32)
	verifier := oauth2.GenerateVerifier()

	// Create stateless session token (JWT)
	sessionToken, err := h.jwtManager.CreateSessionToken(state, verifier, h.sessionTTL)
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	// Store session in CRD (distributed across all pods)
	ctx := r.Context()
	_, err = h.sessionClient.Create(ctx, state, verifier)
	if err != nil {
		log.Printf("Failed to create session CRD: %v", err)
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	// Create OAuth URL with state
	authURL := h.provider.OAuth2Config.AuthCodeURL(
		state,
		oauth2.AccessTypeOffline,
		oauth2.S256ChallengeOption(verifier),
	)

	resp := StartLoginResponse{
		SessionToken: sessionToken,
		LoginURL:     authURL,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (h *LoginHandler) HandleWatch(w http.ResponseWriter, r *http.Request) {
	sessionToken := r.URL.Query().Get("session_token")
	if sessionToken == "" {
		http.Error(w, "No session_token specified", http.StatusBadRequest)
		return
	}

	// Validate session token
	sessionJWT, err := h.jwtManager.ValidateSessionToken(sessionToken)
	if err != nil {
		log.Printf("Watch: Failed to validate session token: %v", err)
		if err == jwt.ErrExpiredToken {
			http.Error(w, "Session expired", http.StatusUnauthorized)
		} else {
			http.Error(w, "Invalid session token", http.StatusUnauthorized)
		}
		return
	}

	state := sessionJWT.State

	// Check if session already completed in CRD
	ctx := r.Context()
	crdSession, err := h.sessionClient.Get(ctx, state)
	if err != nil {
		if apierrors.IsNotFound(err) {
			http.Error(w, "Session not found or expired", http.StatusNotFound)
		} else {
			http.Error(w, "Failed to get session", http.StatusInternalServerError)
		}
		return
	}

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	// If already ready, send immediately
	if crdSession.Status.Ready {
		status := StatusResponse{
			Ready:        true,
			Kubeconfig:   crdSession.Status.Kubeconfig,
			RefreshToken: crdSession.Status.RefreshToken,
		}
		h.sendFinalStatus(w, &status)
		return
	}

	// If there's an error, send immediately
	if crdSession.Status.Error != "" {
		status := StatusResponse{
			Ready: false,
			Error: crdSession.Status.Error,
		}
		h.sendFinalStatus(w, &status)
		return
	}

	// Register local listener for updates
	listener := make(chan StatusResponse, 1)
	h.sseMutex.Lock()
	h.sseListeners[state] = append(h.sseListeners[state], listener)
	h.sseMutex.Unlock()

	// Cleanup listener on exit
	defer func() {
		h.sseMutex.Lock()
		listeners := h.sseListeners[state]
		for i, l := range listeners {
			if l == listener {
				h.sseListeners[state] = append(listeners[:i], listeners[i+1:]...)
				break
			}
		}
		if len(h.sseListeners[state]) == 0 {
			delete(h.sseListeners, state)
		}
		h.sseMutex.Unlock()
		close(listener)
	}()

	flusher, ok := w.(http.Flusher)
	if !ok {
		log.Printf("Watch: Streaming not supported")
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	// Send keepalive every 15 seconds
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case status := <-listener:
			data, _ := json.Marshal(status)
			_, _ = fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
			return
		case <-ticker.C:
			_, _ = fmt.Fprintf(w, ": keepalive\n\n")
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func (h *LoginHandler) sendFinalStatus(w http.ResponseWriter, status *StatusResponse) {
	data, _ := json.Marshal(status)
	_, _ = fmt.Fprintf(w, "data: %s\n\n", data)
}

func (h *LoginHandler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	if state == "" {
		http.Error(w, "Missing state", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	// Get session from CRD to retrieve verifier
	crdSession, err := h.sessionClient.Get(ctx, state)
	if err != nil {
		if apierrors.IsNotFound(err) {
			http.Error(w, "Session not found or expired", http.StatusBadRequest)
		} else {
			http.Error(w, "Failed to get session", http.StatusInternalServerError)
		}
		return
	}

	verifier := crdSession.Spec.Verifier
	if verifier == "" {
		_ = h.sessionClient.UpdateStatus(ctx, state, v1alpha1.OAuthSessionStatus{
			Ready: false,
			Error: "Invalid session",
		})
		http.Error(w, "Invalid session", http.StatusInternalServerError)
		return
	}

	// Handle OAuth errors
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		errDesc := r.URL.Query().Get("error_description")
		_ = h.sessionClient.UpdateStatus(ctx, state, v1alpha1.OAuthSessionStatus{
			Ready: false,
			Error: fmt.Sprintf("%s: %s", errParam, errDesc),
		})
		http.Error(w, errParam, http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		_ = h.sessionClient.UpdateStatus(ctx, state, v1alpha1.OAuthSessionStatus{
			Ready: false,
			Error: "No authorization code returned",
		})
		http.Error(w, "No code returned", http.StatusBadRequest)
		return
	}

	token, err := h.provider.OAuth2Config.Exchange(
		ctx,
		code,
		oauth2.VerifierOption(verifier),
	)
	if err != nil {
		_ = h.sessionClient.UpdateStatus(ctx, state, v1alpha1.OAuthSessionStatus{
			Ready: false,
			Error: fmt.Sprintf("Token exchange failed: %v", err),
		})
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	idToken, ok := token.Extra("id_token").(string)
	if !ok {
		_ = h.sessionClient.UpdateStatus(ctx, state, v1alpha1.OAuthSessionStatus{
			Ready: false,
			Error: "No ID token returned",
		})
		http.Error(w, "No ID token", http.StatusInternalServerError)
		return
	}

	verified, err := h.provider.VerifyIDToken(ctx, idToken)
	if err != nil {
		_ = h.sessionClient.UpdateStatus(ctx, state, v1alpha1.OAuthSessionStatus{
			Ready: false,
			Error: fmt.Sprintf("ID token verification failed: %v", err),
		})
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var claims struct {
		Email  string   `json:"email"`
		Groups []string `json:"groups"`
		Name   string   `json:"name"`
		Sub    string   `json:"sub"`
	}
	if err := verified.Claims(&claims); err != nil {
		log.Printf("AUTH_FAILURE: Failed to extract claims from ID token: %v", err)
		_ = h.sessionClient.UpdateStatus(ctx, state, v1alpha1.OAuthSessionStatus{
			Ready: false,
			Error: "Failed to extract claims",
		})
		http.Error(w, "Failed to extract claims", http.StatusInternalServerError)
		return
	}

	// Validate group membership if required
	if len(h.allowedGroups) > 0 {
		if !h.isUserAuthorized(claims.Groups) {
			log.Printf("AUTH_DENIED: user=%q groups=%v allowed_groups=%v reason=group_not_allowed",
				claims.Email, claims.Groups, h.allowedGroups)
			_ = h.sessionClient.UpdateStatus(ctx, state, v1alpha1.OAuthSessionStatus{
				Ready: false,
				Error: "User is not a member of allowed groups",
			})
			http.Error(w, "Forbidden: user not in allowed groups", http.StatusForbidden)
			return
		}
	}

	// Log successful authentication with details
	log.Printf("AUTH_SUCCESS: user=%q name=%q sub=%q groups=%v cluster=%q",
		claims.Email, claims.Name, claims.Sub, claims.Groups, h.clusterName)

	// Create refresh token (contains OIDC refresh token encrypted)
	oidcRefreshToken := ""
	if token.RefreshToken != "" {
		oidcRefreshToken = token.RefreshToken
	}

	refreshToken, err := h.jwtManager.CreateRefreshToken(
		claims.Email,
		oidcRefreshToken,
		0, // Initial rotation counter
		h.refreshTokenTTL,
	)
	if err != nil {
		_ = h.sessionClient.UpdateStatus(ctx, state, v1alpha1.OAuthSessionStatus{
			Ready: false,
			Error: "Failed to create refresh token",
		})
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Generate kubeconfig
	kubeconfig := h.generateKubeconfig(claims.Email, idToken)

	// Update session status in CRD (triggers watch on all pods)
	err = h.sessionClient.UpdateStatus(ctx, state, v1alpha1.OAuthSessionStatus{
		Ready:        true,
		Kubeconfig:   kubeconfig,
		RefreshToken: refreshToken,
	})
	if err != nil {
		log.Printf("Failed to update session status: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Render success page
	w.Header().Set("Content-Type", "text/html")
	_ = hh.Doctype(
		hh.HTML(
			hh.Head(
				hh.Meta(c.Attr("charset", "UTF-8")),
				hh.Meta(c.Attr("name", "viewport"), c.Attr("content", "width=device-width, initial-scale=1.0")),
				hh.TitleEl(c.Text("Authentication Successful")),
				hh.StyleEl(c.Raw(`
					* {
						margin: 0;
						padding: 0;
						box-sizing: border-box;
					}
					body {
						font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
						background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
						min-height: 100vh;
						display: flex;
						align-items: center;
						justify-content: center;
						color: #e0e0e0;
					}
					.container {
						max-width: 500px;
						width: 100%;
						padding: 40px;
						text-align: center;
					}
					.success-icon {
						width: 80px;
						height: 80px;
						margin: 0 auto 30px;
						border-radius: 50%;
						background: linear-gradient(135deg, #00d2ff 0%, #3a7bd5 100%);
						display: flex;
						align-items: center;
						justify-content: center;
						animation: scaleIn 0.5s ease-out;
					}
					.success-icon svg {
						width: 50px;
						height: 50px;
						stroke: white;
						stroke-width: 3;
						stroke-linecap: round;
						stroke-linejoin: round;
						fill: none;
						animation: drawCheck 0.5s ease-out 0.3s forwards;
						stroke-dasharray: 50;
						stroke-dashoffset: 50;
					}
					@keyframes scaleIn {
						from {
							transform: scale(0);
							opacity: 0;
						}
						to {
							transform: scale(1);
							opacity: 1;
						}
					}
					@keyframes drawCheck {
						to {
							stroke-dashoffset: 0;
						}
					}
					h1 {
						color: #ffffff;
						font-size: 28px;
						margin-bottom: 15px;
						font-weight: 600;
					}
					p {
						color: #b0b0b0;
						font-size: 16px;
						line-height: 1.6;
						margin-bottom: 15px;
					}
					.info {
						background: rgba(255, 255, 255, 0.05);
						border: 1px solid rgba(255, 255, 255, 0.1);
						border-radius: 8px;
						padding: 20px;
						margin: 30px 0;
					}
					.info p {
						color: #90caf9;
						font-size: 14px;
						margin: 0;
					}
					.progress-container {
						width: 100%;
						height: 4px;
						background: rgba(255, 255, 255, 0.1);
						border-radius: 2px;
						overflow: hidden;
						margin-top: 30px;
					}
					.progress-bar {
						height: 100%;
						background: linear-gradient(90deg, #00d2ff 0%, #3a7bd5 100%);
						border-radius: 2px;
						animation: progress 5s linear forwards;
					}
					@keyframes progress {
						from {
							width: 100%;
						}
						to {
							width: 0%;
						}
					}
					.timer {
						color: #808080;
						font-size: 12px;
						margin-top: 10px;
					}
				`)),
				hh.Script(c.Raw(`
					let timeLeft = 5;
					const timerEl = document.getElementById('timer');

					const countdown = setInterval(function() {
						timeLeft--;
						if (timerEl) {
							timerEl.textContent = timeLeft;
						}
						if (timeLeft <= 0) {
							clearInterval(countdown);
							window.close();
						}
					}, 1000);
				`)),
			),
			hh.Body(
				hh.Div(c.Attr("class", "container"),
					hh.Div(c.Attr("class", "success-icon"),
						c.Raw(`<svg viewBox="0 0 50 50"><path d="M 10 25 L 20 35 L 40 15"></path></svg>`),
					),
					hh.H1(c.Text("Authentication Successful!")),
					hh.P(c.Text("You can close this window and return to your terminal.")),
					hh.Div(c.Attr("class", "progress-container"),
						hh.Div(c.Attr("class", "progress-bar")),
					),
					hh.Div(c.Attr("class", "timer"),
						c.Text("Window closes in "),
						hh.Span(c.Attr("id", "timer"), c.Text("5")),
						c.Text(" seconds"),
					),
				),
			),
		),
	).Render(w)
}

func (h *LoginHandler) generateKubeconfig(email, idToken string) string {
	// Generate kubeconfig with exec credential plugin
	// This ensures automatic token refresh without manual intervention
	return fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: %s
  cluster:
    server: %s
    certificate-authority-data: %s
users:
- name: %s
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: kauth
      args:
      - get-token
      interactiveMode: Never
contexts:
- name: %s
  context:
    cluster: %s
    user: %s
current-context: %s
`, h.clusterName, h.clusterServer, h.clusterCA,
		email,
		h.clusterName, h.clusterName, email,
		h.clusterName)
}

// notifyListeners is deprecated - notifications now handled by CRD watch
// Keeping stub for compatibility during migration

func generateRandomString(size int) string {
	b := make([]byte, size)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// isUserAuthorized checks if user belongs to any allowed group
func (h *LoginHandler) isUserAuthorized(userGroups []string) bool {
	if len(h.allowedGroups) == 0 {
		// No group restrictions
		return true
	}

	// Check if user has any of the allowed groups
	for _, userGroup := range userGroups {
		if slices.Contains(h.allowedGroups, userGroup) {
			return true
		}
	}

	return false
}
