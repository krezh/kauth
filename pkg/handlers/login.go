package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"kauth/pkg/jwt"
	"kauth/pkg/oauth"

	"golang.org/x/oauth2"

	. "maragu.dev/gomponents"
	. "maragu.dev/gomponents/html"
)

type LoginHandler struct {
	provider        *oauth.Provider
	jwtManager      *jwt.Manager
	clusterName     string
	clusterServer   string
	clusterCA       string
	sessionTTL      time.Duration
	refreshTokenTTL time.Duration

	// Minimal transient state for SSE delivery only
	sseNotifications map[string]*SSENotification
	sseMutex         sync.RWMutex
}

// SSENotification holds temporary data for SSE delivery
type SSENotification struct {
	Verifier  string // PKCE verifier (needed for callback)
	Listeners []chan StatusResponse
	Result    *StatusResponse // Set when callback completes
	CreatedAt time.Time
}

type StartLoginResponse struct {
	SessionToken string `json:"session_token"` // JWT containing state & verifier
	LoginURL     string `json:"login_url"`
}

type StatusResponse struct {
	Ready        bool   `json:"ready"`
	Kubeconfig   string `json:"kubeconfig,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"` // New: for token rotation
	Error        string `json:"error,omitempty"`
}

func NewLoginHandler(
	provider *oauth.Provider,
	jwtManager *jwt.Manager,
	clusterName, clusterServer, clusterCA string,
	sessionTTL, refreshTokenTTL time.Duration,
) *LoginHandler {
	h := &LoginHandler{
		provider:         provider,
		jwtManager:       jwtManager,
		clusterName:      clusterName,
		clusterServer:    clusterServer,
		clusterCA:        clusterCA,
		sessionTTL:       sessionTTL,
		refreshTokenTTL:  refreshTokenTTL,
		sseNotifications: make(map[string]*SSENotification),
	}

	// Cleanup SSE notifications periodically (30 second TTL)
	go h.cleanupSSENotifications()

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

	// Store minimal state for callback (state -> verifier mapping)
	// This is ephemeral and only needed for OAuth flow completion
	h.sseMutex.Lock()
	h.sseNotifications[state] = &SSENotification{
		Verifier:  verifier,
		Listeners: make([]chan StatusResponse, 0),
		CreatedAt: time.Now(),
	}
	h.sseMutex.Unlock()

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
	json.NewEncoder(w).Encode(resp)
}

func (h *LoginHandler) HandleWatch(w http.ResponseWriter, r *http.Request) {
	sessionToken := r.URL.Query().Get("session_token")
	if sessionToken == "" {
		http.Error(w, "No session_token specified", http.StatusBadRequest)
		return
	}

	// Validate session token
	session, err := h.jwtManager.ValidateSessionToken(sessionToken)
	if err != nil {
		if err == jwt.ErrExpiredToken {
			http.Error(w, "Session expired", http.StatusUnauthorized)
		} else {
			http.Error(w, "Invalid session token", http.StatusUnauthorized)
		}
		return
	}

	// Use state as notification key
	notificationKey := session.State

	h.sseMutex.Lock()
	notification, exists := h.sseNotifications[notificationKey]
	if !exists {
		// Create notification entry
		notification = &SSENotification{
			Listeners: make([]chan StatusResponse, 0),
			CreatedAt: time.Now(),
		}
		h.sseNotifications[notificationKey] = notification
	}

	// Check if result already exists
	if notification.Result != nil {
		h.sseMutex.Unlock()
		h.sendFinalStatus(w, notification.Result)
		return
	}

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	// Create channel for this listener
	listener := make(chan StatusResponse, 1)
	notification.Listeners = append(notification.Listeners, listener)
	h.sseMutex.Unlock()

	flusher, ok := w.(http.Flusher)
	if !ok {
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
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
			return
		case <-ticker.C:
			fmt.Fprintf(w, ": keepalive\n\n")
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func (h *LoginHandler) sendFinalStatus(w http.ResponseWriter, status *StatusResponse) {
	data, _ := json.Marshal(status)
	fmt.Fprintf(w, "data: %s\n\n", data)
}

func (h *LoginHandler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	if state == "" {
		http.Error(w, "Missing state", http.StatusBadRequest)
		return
	}

	// Handle OAuth errors
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		errDesc := r.URL.Query().Get("error_description")
		h.notifyListeners(state, &StatusResponse{
			Ready: false,
			Error: fmt.Sprintf("%s: %s", errParam, errDesc),
		})
		http.Error(w, errParam, http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		h.notifyListeners(state, &StatusResponse{
			Ready: false,
			Error: "No authorization code returned",
		})
		http.Error(w, "No code returned", http.StatusBadRequest)
		return
	}

	// Note: We can't validate the session token here because the browser
	// doesn't send it in the callback. Instead, the client validates it
	// when polling /watch. We use state as the notification key.

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	// We need to get the verifier - but it's in the session token!
	// Problem: Browser callback doesn't have the session token.
	// Solution: Store minimal state mapping temporarily OR change flow.

	// Let's store state->verifier mapping temporarily when /start-login is called
	h.sseMutex.Lock()
	notification := h.sseNotifications[state]
	if notification == nil {
		h.sseMutex.Unlock()
		http.Error(w, "Session not found or expired", http.StatusBadRequest)
		return
	}
	h.sseMutex.Unlock()

	// Wait - we still need the verifier. Let me reconsider...
	// The session token contains the verifier, but we can't access it here.
	// We need to store state->verifier mapping when creating the session.

	// Actually, let's add the verifier to the SSENotification
	// We'll update HandleStartLogin to store it

	verifier := notification.Verifier
	if verifier == "" {
		h.notifyListeners(state, &StatusResponse{
			Ready: false,
			Error: "Invalid session",
		})
		http.Error(w, "Invalid session", http.StatusInternalServerError)
		return
	}

	token, err := h.provider.OAuth2Config.Exchange(
		ctx,
		code,
		oauth2.VerifierOption(verifier),
	)
	if err != nil {
		h.notifyListeners(state, &StatusResponse{
			Ready: false,
			Error: fmt.Sprintf("Token exchange failed: %v", err),
		})
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	idToken, ok := token.Extra("id_token").(string)
	if !ok {
		h.notifyListeners(state, &StatusResponse{
			Ready: false,
			Error: "No ID token returned",
		})
		http.Error(w, "No ID token", http.StatusInternalServerError)
		return
	}

	verified, err := h.provider.VerifyIDToken(ctx, idToken)
	if err != nil {
		h.notifyListeners(state, &StatusResponse{
			Ready: false,
			Error: fmt.Sprintf("ID token verification failed: %v", err),
		})
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var claims struct {
		Email string `json:"email"`
	}
	if err := verified.Claims(&claims); err != nil {
		h.notifyListeners(state, &StatusResponse{
			Ready: false,
			Error: "Failed to extract claims",
		})
		http.Error(w, "Failed to extract claims", http.StatusInternalServerError)
		return
	}

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
		h.notifyListeners(state, &StatusResponse{
			Ready: false,
			Error: "Failed to create refresh token",
		})
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Generate kubeconfig
	kubeconfig := h.generateKubeconfig(claims.Email, idToken)

	// Notify all listeners
	h.notifyListeners(state, &StatusResponse{
		Ready:        true,
		Kubeconfig:   kubeconfig,
		RefreshToken: refreshToken,
	})

	// Render success page
	w.Header().Set("Content-Type", "text/html")
	_ = HTML(
		Head(
			Meta(Charset("UTF-8")),
			Title("Authentication Successful"),
			StyleEl(Raw(`
				body {
					font-family: Arial, sans-serif;
					max-width: 600px;
					margin: 50px auto;
					padding: 20px;
					text-align: center;
				}
				.success {
					color: #4CAF50;
					font-size: 48px;
					margin-bottom: 20px;
				}
				h1 { color: #333; }
				p { color: #666; font-size: 18px; }
			`)),
			Script(Raw(`
				setTimeout(function() {
					window.close();
				}, 5000);
			`)),
		),
		Body(
			Div(Class("success"), Text("✓")),
			H1(Text("Authentication Successful!")),
			P(Text("You can close this window and return to your terminal.")),
			P(
				Style("margin-top: 40px; font-size: 14px;"),
				Text("Your kubeconfig is being configured automatically..."),
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

func (h *LoginHandler) notifyListeners(state string, status *StatusResponse) {
	h.sseMutex.Lock()
	defer h.sseMutex.Unlock()

	notification := h.sseNotifications[state]
	if notification == nil {
		return
	}

	// Store result for any future listeners
	notification.Result = status

	// Notify all active listeners
	for _, listener := range notification.Listeners {
		select {
		case listener <- *status:
		default:
		}
	}
	notification.Listeners = nil
}

func (h *LoginHandler) cleanupSSENotifications() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		h.sseMutex.Lock()
		now := time.Now()
		for key, notification := range h.sseNotifications {
			// Remove notifications older than 30 seconds
			if now.Sub(notification.CreatedAt) > 30*time.Second {
				delete(h.sseNotifications, key)
			}
		}
		h.sseMutex.Unlock()
	}
}

func generateRandomString(size int) string {
	b := make([]byte, size)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
