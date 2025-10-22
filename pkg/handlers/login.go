package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"kauth/pkg/oauth"

	"golang.org/x/oauth2"
)

type LoginHandler struct {
	provider      *oauth.Provider
	clusterName   string
	clusterServer string
	clusterCA     string
	sessions      map[string]*LoginSession
	sessionMutex  sync.RWMutex
}

type LoginSession struct {
	State     string
	Verifier  string
	CreatedAt time.Time
	Token     *oauth2.Token
	UserEmail string
	Ready     bool
	Error     string
	Listeners []chan StatusResponse
}

type StartLoginResponse struct {
	SessionID string `json:"session_id"`
	LoginURL  string `json:"login_url"`
}

type StatusResponse struct {
	Ready      bool   `json:"ready"`
	Kubeconfig string `json:"kubeconfig,omitempty"`
	Error      string `json:"error,omitempty"`
}

func NewLoginHandler(provider *oauth.Provider, clusterName, clusterServer, clusterCA string) *LoginHandler {
	h := &LoginHandler{
		provider:      provider,
		clusterName:   clusterName,
		clusterServer: clusterServer,
		clusterCA:     clusterCA,
		sessions:      make(map[string]*LoginSession),
	}

	go h.cleanupSessions()
	return h
}

func (h *LoginHandler) HandleStartLogin(w http.ResponseWriter, r *http.Request) {
	sessionID := generateSessionID()
	state := generateState()
	verifier := oauth2.GenerateVerifier()

	h.sessionMutex.Lock()
	h.sessions[sessionID] = &LoginSession{
		State:     state,
		Verifier:  verifier,
		CreatedAt: time.Now(),
		Listeners: make([]chan StatusResponse, 0),
	}
	h.sessionMutex.Unlock()

	authURL := h.provider.OAuth2Config.AuthCodeURL(
		fmt.Sprintf("%s:%s", sessionID, state),
		oauth2.AccessTypeOffline,
		oauth2.S256ChallengeOption(verifier),
	)

	resp := StartLoginResponse{
		SessionID: sessionID,
		LoginURL:  authURL,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (h *LoginHandler) HandleWatch(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session")
	if sessionID == "" {
		http.Error(w, "No session specified", http.StatusBadRequest)
		return
	}

	h.sessionMutex.Lock()
	session, exists := h.sessions[sessionID]
	if !exists {
		h.sessionMutex.Unlock()
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// Create channel for this listener
	listener := make(chan StatusResponse, 1)
	session.Listeners = append(session.Listeners, listener)
	h.sessionMutex.Unlock()

	// Send initial status if already ready/error
	if session.Ready || session.Error != "" {
		h.sendFinalStatus(w, session)
		return
	}

	// Wait for completion
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

func (h *LoginHandler) sendFinalStatus(w http.ResponseWriter, session *LoginSession) {
	var status StatusResponse

	if session.Error != "" {
		status = StatusResponse{
			Ready: false,
			Error: session.Error,
		}
	} else if session.Ready && session.Token != nil {
		idToken, _ := session.Token.Extra("id_token").(string)
		kubeconfig := h.generateKubeconfig(session.UserEmail, idToken)
		status = StatusResponse{
			Ready:      true,
			Kubeconfig: kubeconfig,
		}
	}

	data, _ := json.Marshal(status)
	fmt.Fprintf(w, "data: %s\n\n", data)
}

func (h *LoginHandler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	stateParam := r.URL.Query().Get("state")
	if stateParam == "" {
		http.Error(w, "Missing state", http.StatusBadRequest)
		return
	}

	// Split state into sessionID:state (split on first colon only)
	parts := strings.SplitN(stateParam, ":", 2)
	if len(parts) != 2 {
		http.Error(w, "Invalid state format", http.StatusBadRequest)
		return
	}
	sessionID := parts[0]
	state := parts[1]

	h.sessionMutex.Lock()
	session, exists := h.sessions[sessionID]
	if !exists {
		h.sessionMutex.Unlock()
		http.Error(w, "Invalid session", http.StatusBadRequest)
		return
	}
	h.sessionMutex.Unlock()

	if state != session.State {
		h.notifyListeners(session, StatusResponse{
			Ready: false,
			Error: "Invalid state parameter",
		})
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	if errParam := r.URL.Query().Get("error"); errParam != "" {
		errDesc := r.URL.Query().Get("error_description")
		h.notifyListeners(session, StatusResponse{
			Ready: false,
			Error: fmt.Sprintf("%s: %s", errParam, errDesc),
		})
		http.Error(w, errParam, http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		h.notifyListeners(session, StatusResponse{
			Ready: false,
			Error: "No authorization code returned",
		})
		http.Error(w, "No code returned", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	token, err := h.provider.OAuth2Config.Exchange(
		ctx,
		code,
		oauth2.VerifierOption(session.Verifier),
	)
	if err != nil {
		h.notifyListeners(session, StatusResponse{
			Ready: false,
			Error: fmt.Sprintf("Token exchange failed: %v", err),
		})
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	idToken, ok := token.Extra("id_token").(string)
	if !ok {
		h.notifyListeners(session, StatusResponse{
			Ready: false,
			Error: "No ID token returned",
		})
		http.Error(w, "No ID token", http.StatusInternalServerError)
		return
	}

	verified, err := h.provider.VerifyIDToken(ctx, idToken)
	if err != nil {
		h.notifyListeners(session, StatusResponse{
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
		h.notifyListeners(session, StatusResponse{
			Ready: false,
			Error: "Failed to extract claims",
		})
		http.Error(w, "Failed to extract claims", http.StatusInternalServerError)
		return
	}

	h.sessionMutex.Lock()
	session.Token = token
	session.UserEmail = claims.Email
	session.Ready = true
	h.sessionMutex.Unlock()

	// Notify all listeners
	kubeconfig := h.generateKubeconfig(claims.Email, idToken)
	h.notifyListeners(session, StatusResponse{
		Ready:      true,
		Kubeconfig: kubeconfig,
	})

	// Success page
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
    <title>Authentication Successful</title>
    <style>
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
    </style>
</head>
<body>
    <div class="success">✓</div>
    <h1>Authentication Successful!</h1>
    <p>You can close this window and return to your terminal.</p>
    <p style="margin-top: 40px; font-size: 14px;">Your kubeconfig is being configured automatically...</p>
</body>
</html>`)
}

func (h *LoginHandler) generateKubeconfig(email, idToken string) string {
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
    token: %s
contexts:
- name: %s
  context:
    cluster: %s
    user: %s
current-context: %s
`, h.clusterName, h.clusterServer, h.clusterCA,
		email, idToken,
		h.clusterName, h.clusterName, email,
		h.clusterName)
}

func (h *LoginHandler) notifyListeners(session *LoginSession, status StatusResponse) {
	h.sessionMutex.Lock()
	defer h.sessionMutex.Unlock()

	session.Ready = status.Ready
	session.Error = status.Error

	for _, listener := range session.Listeners {
		select {
		case listener <- status:
		default:
		}
	}
	session.Listeners = nil
}

func (h *LoginHandler) cleanupSessions() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		h.sessionMutex.Lock()
		now := time.Now()
		for id, session := range h.sessions {
			if now.Sub(session.CreatedAt) > 15*time.Minute {
				delete(h.sessions, id)
			}
		}
		h.sessionMutex.Unlock()
	}
}

func generateSessionID() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func generateState() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
