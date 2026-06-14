package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"sync"
	"time"

	v1alpha1 "kauth/pkg/apis/kauth.io/v1alpha1"
	"kauth/pkg/audit"
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
	kubeconfigGen   *KubeconfigGenerator
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
	SessionID    string `json:"session_id,omitempty"`
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
		provider:   provider,
		jwtManager: jwtManager,
		kubeconfigGen: &KubeconfigGenerator{
			ClusterName:   clusterName,
			ClusterServer: clusterServer,
			ClusterCA:     clusterCA,
		},
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
	// Generate session ID and PKCE verifier
	sessionID := generateRandomString(32)
	verifier := oauth2.GenerateVerifier()

	// Create stateless session token (JWT)
	sessionToken, err := h.jwtManager.CreateSessionToken(sessionID, verifier, h.sessionTTL)
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	// Store session in CRD (distributed across all pods)
	ctx := r.Context()
	_, err = h.sessionClient.Create(ctx, sessionID, verifier, "")
	if err != nil {
		slog.ErrorContext(ctx, "failed to create session CRD", "error", err)
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	// Create OAuth URL with state
	authURL := h.provider.OAuth2Config.AuthCodeURL(
		sessionID,
		oauth2.AccessTypeOffline,
		oauth2.S256ChallengeOption(verifier),
	)

	resp := StartLoginResponse{
		SessionToken: sessionToken,
		LoginURL:     authURL,
	}
	writeJSON(w, resp)
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
		slog.WarnContext(r.Context(), "watch: failed to validate session token", "error", err)
		if errors.Is(err, jwt.ErrExpiredToken) {
			http.Error(w, "Session expired", http.StatusUnauthorized)
		} else {
			http.Error(w, "Invalid session token", http.StatusUnauthorized)
		}
		return
	}

	sessionID := sessionJWT.SessionID
	ctx := r.Context()

	// Check streaming support before touching response headers.
	flusher, ok := w.(http.Flusher)
	if !ok {
		slog.ErrorContext(ctx, "watch: streaming not supported")
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	// Register listener BEFORE reading CRD status so we cannot miss an event
	// that fires in the window between the CRD read and the registration.
	listener := make(chan StatusResponse, 1)
	h.sseMutex.Lock()
	h.sseListeners[sessionID] = append(h.sseListeners[sessionID], listener)
	h.sseMutex.Unlock()

	// Cleanup listener on exit.
	// Do not close(listener): watchSessions holds a copy of the slice and may
	// send to this channel after we return. The buffered channel is GC'd.
	defer func() {
		h.sseMutex.Lock()
		listeners := h.sseListeners[sessionID]
		for i, l := range listeners {
			if l == listener {
				h.sseListeners[sessionID] = append(listeners[:i], listeners[i+1:]...)
				break
			}
		}
		if len(h.sseListeners[sessionID]) == 0 {
			delete(h.sseListeners, sessionID)
		}
		h.sseMutex.Unlock()
	}()

	// Read CRD status after registering listener — catches sessions that
	// completed between token validation and listener registration.
	crdSession, err := h.sessionClient.Get(ctx, sessionID)
	if err != nil {
		if apierrors.IsNotFound(err) {
			http.Error(w, "Session not found or expired", http.StatusNotFound)
		} else {
			http.Error(w, "Failed to get session", http.StatusInternalServerError)
		}
		return
	}

	// Set SSE headers — no more error returns after this point.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	// If already active, send immediately.
	if crdSession.Status.Phase == v1alpha1.SessionActive {
		kubeconfig := h.kubeconfigGen.Generate(crdSession.Status.Email, crdSession.Status.Username)
		status := StatusResponse{
			Ready:        true,
			Kubeconfig:   kubeconfig,
			RefreshToken: crdSession.Status.RefreshToken,
			SessionID:    crdSession.Spec.SessionID,
		}
		h.sendFinalStatus(w, &status)
		return
	}

	// If there's an error, send immediately.
	if crdSession.Status.Error != "" {
		h.sendFinalStatus(w, &StatusResponse{Ready: false, Error: crdSession.Status.Error})
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
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
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
			Phase: v1alpha1.SessionPending,
			Error: "Invalid session",
		})
		http.Error(w, "Invalid session", http.StatusInternalServerError)
		return
	}

	// Handle OAuth errors
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		errDesc := r.URL.Query().Get("error_description")
		_ = h.sessionClient.UpdateStatus(ctx, state, v1alpha1.OAuthSessionStatus{
			Phase: v1alpha1.SessionPending,
			Error: fmt.Sprintf("%s: %s", errParam, errDesc),
		})
		http.Error(w, errParam, http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		_ = h.sessionClient.UpdateStatus(ctx, state, v1alpha1.OAuthSessionStatus{
			Phase: v1alpha1.SessionPending,
			Error: "No authorization code returned",
		})
		http.Error(w, "No code returned", http.StatusBadRequest)
		return
	}

	httpClient := oauth.NewMetricsHTTPClient("token_exchange")
	ctxWithClient := context.WithValue(ctx, oauth2.HTTPClient, httpClient)

	token, err := h.provider.OAuth2Config.Exchange(
		ctxWithClient,
		code,
		oauth2.VerifierOption(verifier),
	)
	if err != nil {
		slog.ErrorContext(ctx, "token exchange failed", "error", err)
		_ = h.sessionClient.UpdateStatus(ctx, state, v1alpha1.OAuthSessionStatus{
			Phase: v1alpha1.SessionPending,
			Error: "Token exchange failed",
		})
		http.Error(w, "Authentication failed", http.StatusInternalServerError)
		return
	}

	idToken, ok := token.Extra("id_token").(string)
	if !ok {
		_ = h.sessionClient.UpdateStatus(ctx, state, v1alpha1.OAuthSessionStatus{
			Phase: v1alpha1.SessionPending,
			Error: "No ID token returned",
		})
		http.Error(w, "Authentication failed", http.StatusInternalServerError)
		return
	}

	claims, _, err := VerifyAndExtractClaims(ctx, h.provider, idToken)
	if err != nil {
		slog.ErrorContext(ctx, "ID token verification failed", "error", err)
		_ = h.sessionClient.UpdateStatus(ctx, state, v1alpha1.OAuthSessionStatus{
			Phase: v1alpha1.SessionPending,
			Error: "Token verification failed",
		})
		http.Error(w, "Authentication failed", http.StatusInternalServerError)
		return
	}

	// Validate group membership if required
	if len(h.allowedGroups) > 0 {
		if !h.isUserAuthorized(claims.Groups) {
			audit.AuthorizationDeny(ctx, r, claims.Email, claims.Groups, h.allowedGroups)
			_ = h.sessionClient.UpdateStatus(ctx, state, v1alpha1.OAuthSessionStatus{
				Phase: v1alpha1.SessionPending,
				Error: "User is not a member of allowed groups",
			})
			http.Error(w, "Forbidden: user not in allowed groups", http.StatusForbidden)
			return
		}
		audit.AuthorizationAllow(ctx, r, claims.Email, claims.Groups)
	}

	// Log successful authentication
	audit.LoginSuccess(ctx, r, claims.Email, h.kubeconfigGen.ClusterName, claims.Groups)
	slog.InfoContext(ctx, "Authentication successful",
		"user", claims.Email,
		"name", claims.Name,
		"sub", claims.Sub,
		"groups", claims.Groups,
		"cluster", h.kubeconfigGen.ClusterName,
	)

	// Create refresh token (contains OIDC refresh token encrypted)
	refreshToken, err := h.jwtManager.CreateRefreshToken(
		claims.Email,
		token.RefreshToken,
		state,
		0,
		h.refreshTokenTTL,
	)
	if err != nil {
		_ = h.sessionClient.UpdateStatus(ctx, state, v1alpha1.OAuthSessionStatus{
			Phase: v1alpha1.SessionPending,
			Error: "Failed to create refresh token",
		})
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	err = h.sessionClient.UpdateStatus(ctx, state, v1alpha1.OAuthSessionStatus{
		Phase:        v1alpha1.SessionActive,
		Email:        claims.Email,
		Username:     claims.PreferredUsername,
		RefreshToken: refreshToken,
	})
	if err != nil {
		slog.ErrorContext(ctx, "failed to update session status", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	if err := h.sessionClient.UpdateUserID(ctx, state, claims.Email); err != nil {
		slog.WarnContext(ctx, "failed to set session user ID", "session", state[:8], "error", err)
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
