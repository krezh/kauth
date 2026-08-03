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
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	v1alpha1 "kauth/pkg/apis/kauth.io/v1alpha1"
	"kauth/pkg/audit"
	"kauth/pkg/jwt"
	"kauth/pkg/oauth"
	"kauth/pkg/session"

	"golang.org/x/oauth2"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

type LoginHandler struct {
	provider          *oauth.Provider
	jwtManager        *jwt.Manager
	kubeconfigGen     *KubeconfigGenerator
	sessionTTL        time.Duration
	refreshTokenTTL   time.Duration
	sessionHistoryTTL time.Duration
	allowedGroups     []string
	baseURL           string
	secureCookie      bool

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
		baseURL:           baseURL,
		secureCookie:      strings.HasPrefix(baseURL, "https://"),
		sessionClient:     sessionClient,
		sseListeners:      make(map[string][]chan StatusResponse),
	}

	// Start watching for session updates from CRD
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
	sessionToken, _, err := h.createLogin(r.Context(), jwt.LoginModeCLI)
	if err != nil {
		slog.ErrorContext(r.Context(), "failed to create login", "error", err)
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}
	writeJSON(w, StartLoginResponse{
		SessionToken: sessionToken,
		LoginURL:     h.baseURL + "/login?session_token=" + url.QueryEscape(sessionToken),
	})
}

func (h *LoginHandler) createLogin(ctx context.Context, mode string) (string, string, error) {
	// Generate session ID and PKCE verifier
	sessionID := generateRandomString(32)
	verifier := oauth2.GenerateVerifier()

	// Create stateless session token (JWT)
	sessionToken, err := h.jwtManager.CreateSessionTokenForMode(sessionID, verifier, mode, h.sessionTTL)
	if err != nil {
		return "", "", err
	}

	// Store session in CRD (distributed across all pods)
	_, err = h.sessionClient.Create(ctx, sessionID, verifier, "")
	if err != nil {
		return "", "", err
	}
	return sessionToken, sessionID, nil
}

func (h *LoginHandler) HandleBrowserLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sessionToken := r.URL.Query().Get("session_token")
	if sessionToken == "" {
		var err error
		sessionToken, _, err = h.createLogin(r.Context(), jwt.LoginModeDashboard)
		if err != nil {
			slog.ErrorContext(r.Context(), "failed to create browser login", "error", err)
			http.Error(w, "Failed to create session", http.StatusInternalServerError)
			return
		}
	}
	transaction, err := h.jwtManager.ValidateSessionToken(sessionToken)
	if err != nil {
		http.Error(w, "Invalid login session", http.StatusBadRequest)
		return
	}
	crdSession, err := h.sessionClient.Get(r.Context(), transaction.SessionID)
	if err != nil || crdSession.Status.Phase != v1alpha1.SessionPending ||
		subtle.ConstantTimeCompare([]byte(transaction.Verifier), []byte(crdSession.Spec.Verifier)) != 1 {
		http.Error(w, "Invalid login session", http.StatusBadRequest)
		return
	}
	h.setBrowserCookie(w, loginBindingCookieName(transaction.SessionID), sessionToken, "/callback", transaction.ExpiresAt)
	config := *h.provider.OAuth2Config
	if transaction.Mode == jwt.LoginModeDashboard {
		config.Scopes = slices.DeleteFunc(append([]string(nil), config.Scopes...), func(scope string) bool { return scope == "offline_access" })
	}
	http.Redirect(w, r, config.AuthCodeURL(
		transaction.SessionID,
		oauth2.AccessTypeOffline,
		oauth2.S256ChallengeOption(transaction.Verifier),
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
	if sessionJWT.Mode != jwt.LoginModeCLI {
		http.Error(w, "Invalid CLI login session", http.StatusUnauthorized)
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
			APIToken:     crdSession.Status.APIToken,
		}
		if crdSession.Status.APIToken != "" {
			if apiCredential, err := h.jwtManager.DecodeAPIToken(crdSession.Status.APIToken); err == nil {
				status.SessionExpiry = apiCredential.ExpiresAt
			}
		}
		h.sendFinalStatus(w, &status)
		return
	}

	// If there's an error, send immediately.
	if crdSession.Status.Error != "" {
		h.sendFinalStatus(w, &StatusResponse{Ready: false, Error: crdSession.Status.Error})
		return
	}

	// Send a keepalive every 5 seconds. This must stay well below any
	// intermediate proxy idle timeout (e.g. Envoy's connectionIdleTimeout)
	// so the long-lived stream is never reaped while waiting for login.
	ticker := time.NewTicker(5 * time.Second)
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
	bindingCookieName := loginBindingCookieName(state)
	bindingCookie, err := r.Cookie(bindingCookieName)
	if err != nil {
		http.Error(w, "Login session expired", http.StatusBadRequest)
		return
	}
	binding, err := h.jwtManager.ValidateSessionToken(bindingCookie.Value)
	if err != nil || subtle.ConstantTimeCompare([]byte(binding.SessionID), []byte(state)) != 1 {
		http.Error(w, "Invalid login state", http.StatusBadRequest)
		return
	}

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
	if crdSession.Status.Phase != v1alpha1.SessionPending ||
		subtle.ConstantTimeCompare([]byte(binding.Verifier), []byte(crdSession.Spec.Verifier)) != 1 {
		http.Error(w, "Invalid login session", http.StatusBadRequest)
		return
	}
	if err := h.sessionClient.ClaimLogin(ctx, state); err != nil {
		http.Error(w, "Login session already used", http.StatusConflict)
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

	claims, verifiedIDToken, err := VerifyAndExtractClaims(ctx, h.provider, idToken)
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
	if binding.Mode == jwt.LoginModeDashboard {
		if err := h.sessionClient.Delete(ctx, state); err != nil {
			slog.ErrorContext(ctx, "failed to consume dashboard login", "error", err)
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		h.completeBrowserLogin(w, r, bindingCookieName, claims, verifiedIDToken.Issuer, verifiedIDToken.Expiry)
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
		_ = h.sessionClient.UpdateStatus(ctx, state, v1alpha1.OAuthSessionStatus{
			Phase: v1alpha1.SessionPending,
			Error: "Failed to create refresh token",
		})
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	apiToken, err := h.jwtManager.CreateAPIToken(state, h.refreshTokenTTL)
	if err != nil {
		_ = h.sessionClient.UpdateStatus(ctx, state, v1alpha1.OAuthSessionStatus{
			Phase: v1alpha1.SessionPending,
			Error: "Failed to create API token",
		})
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	err = h.sessionClient.UpdateStatus(ctx, state, v1alpha1.OAuthSessionStatus{
		Phase:        v1alpha1.SessionActive,
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
	h.completeBrowserLogin(w, r, bindingCookieName, claims, verifiedIDToken.Issuer, verifiedIDToken.Expiry)
}

func (h *LoginHandler) completeBrowserLogin(w http.ResponseWriter, r *http.Request, bindingCookieName string, claims *OIDCClaims, issuer string, idTokenExpiry time.Time) {
	ttl := dashboardSessionTTL
	if remaining := time.Until(idTokenExpiry); remaining < ttl {
		ttl = remaining
	}
	dashboardToken, err := h.jwtManager.CreateDashboardSessionToken(claims.Email, claims.Sub, issuer, claims.Groups, ttl)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	h.clearBrowserCookie(w, bindingCookieName, "/callback")
	h.setBrowserCookie(w, dashboardCookie, dashboardToken, "/", time.Now().Add(ttl))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (h *LoginHandler) setBrowserCookie(w http.ResponseWriter, name, value, path string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: path, Expires: expires, MaxAge: int(time.Until(expires).Seconds()), HttpOnly: true, Secure: h.secureCookie, SameSite: http.SameSiteLaxMode})
}

func (h *LoginHandler) clearBrowserCookie(w http.ResponseWriter, name, path string) {
	http.SetCookie(w, &http.Cookie{Name: name, Path: path, MaxAge: -1, HttpOnly: true, Secure: h.secureCookie, SameSite: http.SameSiteLaxMode})
}

func loginBindingCookieName(state string) string {
	return dashboardLoginCookie + "_" + state
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
