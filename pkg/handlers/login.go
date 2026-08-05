package handlers

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"kauth/pkg/audit"
	"kauth/pkg/jwt"
	"kauth/pkg/oauth"
	"kauth/pkg/session"

	"golang.org/x/oauth2"
)

type LoginHandler struct {
	provider          *oauth.Provider
	jwtManager        *jwt.Manager
	kubeconfigGen     *KubeconfigGenerator
	sessionTTL        time.Duration
	refreshTokenTTL   time.Duration
	sessionHistoryTTL time.Duration
	allowedGroups     []string
	secureCookie      bool

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
	Ready         bool      `json:"ready"`
	Kubeconfig    string    `json:"kubeconfig,omitempty"`
	RefreshToken  string    `json:"refresh_token,omitempty"`
	SessionID     string    `json:"session_id,omitempty"`
	APIToken      string    `json:"api_token,omitempty"`
	SessionExpiry time.Time `json:"session_expiry,omitempty"`
	Error         string    `json:"error,omitempty"`
}

func NewLoginHandler(
	provider *oauth.Provider,
	jwtManager *jwt.Manager,
	clusterName, clusterServer, baseURL string,
	sessionTTL, refreshTokenTTL, sessionHistoryTTL time.Duration,
	allowedGroups []string,
	sessionClient *session.Client,
) *LoginHandler {
	h := &LoginHandler{
		provider:   provider,
		jwtManager: jwtManager,
		kubeconfigGen: &KubeconfigGenerator{
			ClusterName:   clusterName,
			ClusterServer: clusterServer,
		},
		sessionTTL:        sessionTTL,
		refreshTokenTTL:   refreshTokenTTL,
		sessionHistoryTTL: sessionHistoryTTL,
		allowedGroups:     allowedGroups,
		secureCookie:      strings.HasPrefix(baseURL, "https://"),
		sessionClient:     sessionClient,
		sseListeners:      make(map[string][]chan StatusResponse),
	}

	go h.watchSessions()

	// Cleanup old sessions periodically (30 second TTL)
	go h.cleanupSessions()

	return h
}

func (h *LoginHandler) HandleStartLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sessionToken, sessionID, verifier, err := h.createCLILogin(r.Context())
	if err != nil {
		slog.ErrorContext(r.Context(), "failed to create login", "error", err)
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}
	writeJSON(w, StartLoginResponse{
		SessionToken: sessionToken,
		LoginURL: h.provider.OAuth2Config.AuthCodeURL(
			sessionID,
			oauth2.AccessTypeOffline,
			oauth2.S256ChallengeOption(verifier),
		),
	})
}

func (h *LoginHandler) createCLILogin(ctx context.Context) (string, string, string, error) {
	// Generate session ID and PKCE verifier
	sessionID := generateRandomString(32)
	verifier := oauth2.GenerateVerifier()

	// Create stateless session token (JWT)
	sessionToken, err := h.jwtManager.CreateSessionToken(sessionID, verifier, h.sessionTTL)
	if err != nil {
		return "", "", "", err
	}

	// Store session in CRD (distributed across all pods)
	_, err = h.sessionClient.Create(ctx, sessionID, verifier, "")
	if err != nil {
		return "", "", "", err
	}
	return sessionToken, sessionID, verifier, nil
}

func (h *LoginHandler) HandleBrowserLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	state, err := oauth.GenerateState()
	if err != nil {
		http.Error(w, "Failed to create login", http.StatusInternalServerError)
		return
	}
	verifier := oauth2.GenerateVerifier()
	binding, err := h.jwtManager.CreateDashboardLoginToken(state, verifier, dashboardLoginTTL)
	if err != nil {
		http.Error(w, "Failed to create login", http.StatusInternalServerError)
		return
	}
	h.setBrowserCookie(w, dashboardLoginCookieName(h.secureCookie), binding, dashboardLoginCookiePath(h.secureCookie), time.Now().Add(dashboardLoginTTL), http.SameSiteLaxMode)
	config := *h.provider.OAuth2Config
	config.Scopes = slices.DeleteFunc(append([]string(nil), config.Scopes...), func(scope string) bool { return scope == "offline_access" })
	http.Redirect(w, r, config.AuthCodeURL(
		state,
		oauth2.S256ChallengeOption(verifier),
	), http.StatusFound)
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
		if errors.Is(err, session.ErrSessionNotFound) {
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

	// If the session already completed, send immediately.
	if status := h.loginStatus(crdSession); status != nil {
		h.sendFinalStatus(w, status)
		return
	}

	// Send a keepalive every 5 seconds. This must stay well below any
	// intermediate proxy idle timeout (e.g. Envoy's connectionIdleTimeout)
	// so the long-lived stream is never reaped while waiting for login.
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	ticks := 0
	for {
		select {
		case status := <-listener:
			data, _ := json.Marshal(status)
			_, _ = fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
			return
		case <-ticker.C:
			ticks++
			// LISTEN/NOTIFY cannot replay events emitted while the hub was
			// disconnected, so re-read the session periodically to recover a
			// completion whose notification was never delivered.
			if ticks%watchPollTicks == 0 {
				if status := h.pollLoginStatus(r, sessionID); status != nil {
					h.sendFinalStatus(w, status)
					return
				}
			}
			_, _ = fmt.Fprintf(w, ": keepalive\n\n")
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

// watchPollTicks is how many keepalive ticks pass between session re-reads.
const watchPollTicks = 3

func (h *LoginHandler) pollLoginStatus(r *http.Request, sessionID string) *StatusResponse {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	sess, err := h.sessionClient.Get(ctx, sessionID)
	if err != nil {
		return nil
	}
	return h.loginStatus(sess)
}

// loginStatus renders the terminal status of a session, or nil while it is still in progress.
func (h *LoginHandler) loginStatus(sess *session.Session) *StatusResponse {
	if sess.Phase != session.PhaseActive && sess.Error == "" {
		return nil
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
	return &status
}

func (h *LoginHandler) sendFinalStatus(w http.ResponseWriter, status *StatusResponse) {
	data, _ := json.Marshal(status)
	_, _ = fmt.Fprintf(w, "data: %s\n\n", data)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

func (h *LoginHandler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	state := r.URL.Query().Get("state")
	if state == "" {
		http.Error(w, "Missing state", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	dashboardMode := false
	verifier := ""
	loginCookieName := dashboardLoginCookieName(h.secureCookie)
	loginCookiePath := dashboardLoginCookiePath(h.secureCookie)
	if bindingCookie, err := r.Cookie(loginCookieName); err == nil {
		binding, err := h.jwtManager.ValidateDashboardLoginToken(bindingCookie.Value)
		if err != nil {
			h.clearBrowserCookie(w, loginCookieName, loginCookiePath)
		} else if subtle.ConstantTimeCompare([]byte(binding.State), []byte(state)) == 1 {
			h.clearBrowserCookie(w, loginCookieName, loginCookiePath)
			dashboardMode = true
			verifier = binding.Verifier
		}
	}
	if !dashboardMode {
		crdSession, err := h.sessionClient.Get(ctx, state)
		if err != nil {
			if errors.Is(err, session.ErrSessionNotFound) {
				http.Error(w, "Session not found or expired", http.StatusBadRequest)
			} else {
				http.Error(w, "Failed to get session", http.StatusInternalServerError)
			}
			return
		}
		if crdSession.Phase != session.PhasePending {
			http.Error(w, "Invalid login session", http.StatusBadRequest)
			return
		}
		if err := h.sessionClient.ClaimLogin(ctx, state); err != nil {
			if errors.Is(err, session.ErrLoginAlreadyClaimed) {
				http.Error(w, "Login session already used", http.StatusConflict)
				return
			}
			slog.ErrorContext(ctx, "failed to claim login session", "error", err)
			http.Error(w, "Failed to start login", http.StatusInternalServerError)
			return
		}
		verifier = crdSession.Verifier
	}
	recordLoginError := func(message string) {
		if !dashboardMode {
			_ = h.sessionClient.UpdateStatus(ctx, state, session.Status{Phase: session.PhaseFailed, Error: message})
		}
	}
	if verifier == "" {
		recordLoginError("Invalid session")
		http.Error(w, "Invalid session", http.StatusInternalServerError)
		return
	}

	// Handle OAuth errors
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		errDesc := r.URL.Query().Get("error_description")
		recordLoginError(fmt.Sprintf("%s: %s", errParam, errDesc))
		http.Error(w, errParam, http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		recordLoginError("No authorization code returned")
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
		recordLoginError("Token exchange failed")
		http.Error(w, "Authentication failed", http.StatusInternalServerError)
		return
	}

	idToken, ok := token.Extra("id_token").(string)
	if !ok {
		recordLoginError("No ID token returned")
		http.Error(w, "Authentication failed", http.StatusInternalServerError)
		return
	}

	claims, verifiedIDToken, err := VerifyAndExtractClaims(ctx, h.provider, idToken)
	if err != nil {
		slog.ErrorContext(ctx, "ID token verification failed", "error", err)
		recordLoginError("Token verification failed")
		http.Error(w, "Authentication failed", http.StatusInternalServerError)
		return
	}
	if claims.Email == "" {
		recordLoginError("Identity provider did not return an email address")
		http.Error(w, "Authentication failed: identity provider did not return an email address", http.StatusForbidden)
		return
	}

	// Validate group membership if required
	if len(h.allowedGroups) > 0 {
		if !h.isUserAuthorized(claims.Groups) {
			audit.AuthorizationDeny(ctx, r, claims.Email, claims.Groups, h.allowedGroups)
			recordLoginError("User is not a member of allowed groups")
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
	if dashboardMode {
		h.completeBrowserLogin(w, r, claims, verifiedIDToken.Issuer, verifiedIDToken.Expiry)
		return
	}

	// Create refresh token (contains OIDC refresh token encrypted)
	refreshToken, err := h.jwtManager.CreateRefreshToken(
		claims.Email,
		token.RefreshToken,
		state,
		0,
		h.refreshTokenTTL,
	)
	if err != nil {
		recordLoginError("Failed to create refresh token")
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	apiToken, err := h.jwtManager.CreateAPIToken(state, h.refreshTokenTTL)
	if err != nil {
		recordLoginError("Failed to create API token")
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	err = h.sessionClient.UpdateStatus(ctx, state, session.Status{
		Phase:        session.PhaseActive,
		Email:        claims.Email,
		Username:     claims.PreferredUsername,
		Subject:      claims.Sub,
		Issuer:       verifiedIDToken.Issuer,
		RefreshToken: refreshToken,
		Groups:       claims.Groups,
		APIToken:     apiToken,
	})
	if err != nil {
		slog.ErrorContext(ctx, "failed to update session status", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	if err := h.sessionClient.UpdateUserID(ctx, state, claims.Email); err != nil {
		slog.WarnContext(ctx, "failed to set session user ID", "session", state[:8], "error", err)
	}
	// CLI callbacks are not browser-bound, so they must not establish a dashboard session.
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (h *LoginHandler) completeBrowserLogin(w http.ResponseWriter, r *http.Request, claims *OIDCClaims, issuer string, idTokenExpiry time.Time) {
	ttl := dashboardSessionTTL
	if remaining := time.Until(idTokenExpiry); remaining < ttl {
		ttl = remaining
	}
	dashboardToken, err := h.jwtManager.CreateDashboardSessionToken(claims.Email, claims.Sub, issuer, claims.Groups, ttl)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	h.setBrowserCookie(w, dashboardCookieName(h.secureCookie), dashboardToken, "/", time.Now().Add(ttl), http.SameSiteLaxMode)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (h *LoginHandler) setBrowserCookie(w http.ResponseWriter, name, value, path string, expires time.Time, sameSite http.SameSite) {
	// The dashboard lives at /. API and Kubernetes routes strip cookies before dispatch.
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: path, Expires: expires, MaxAge: int(time.Until(expires).Seconds()), HttpOnly: true, Secure: h.secureCookie, SameSite: sameSite})
}

func (h *LoginHandler) clearBrowserCookie(w http.ResponseWriter, name, path string) {
	http.SetCookie(w, &http.Cookie{Name: name, Path: path, MaxAge: -1, HttpOnly: true, Secure: h.secureCookie, SameSite: http.SameSiteLaxMode})
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
