package handlers

import (
	"context"
	"crypto/subtle"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	v1alpha1 "kauth/pkg/apis/kauth.io/v1alpha1"
	"kauth/pkg/audit"
	"kauth/pkg/jwt"
	"kauth/pkg/oauth"
	"kauth/pkg/session"

	"golang.org/x/oauth2"
)

const (
	dashboardCookie      = "kauth_dashboard"
	dashboardLoginCookie = "kauth_dashboard_login"
	dashboardLoginTTL    = 10 * time.Minute
	dashboardSessionTTL  = 15 * time.Minute
)

type DashboardHandler struct {
	getProvider   func() *oauth.Provider
	jwtManager    *jwt.Manager
	sessions      *session.Client
	requests      audit.RequestStore
	baseURL       string
	clusterName   string
	allowedGroups []string
	adminGroups   []string
	secureCookie  bool
}

type DashboardConfig struct {
	BaseURL       string
	ClusterName   string
	AllowedGroups []string
	AdminGroups   []string
}

func NewDashboardHandler(getProvider func() *oauth.Provider, jwtManager *jwt.Manager, sessions *session.Client, requests audit.RequestStore, config DashboardConfig) *DashboardHandler {
	return &DashboardHandler{
		getProvider: getProvider, jwtManager: jwtManager, sessions: sessions, requests: requests,
		baseURL: config.BaseURL, clusterName: config.ClusterName,
		allowedGroups: config.AllowedGroups, adminGroups: config.AdminGroups,
		secureCookie: strings.HasPrefix(config.BaseURL, "https://"),
	}
}

func (h *DashboardHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/dashboard/login":
		h.handleLogin(w, r)
	case "/dashboard/callback":
		h.handleCallback(w, r)
	case "/dashboard/logout":
		h.handleLogout(w, r)
	case "/dashboard", "/dashboard/":
		h.requireSession(h.handleOverview)(w, r)
	default:
		if strings.HasPrefix(r.URL.Path, "/dashboard/sessions/") {
			h.requireSession(h.handleSession)(w, r)
			return
		}
		http.NotFound(w, r)
	}
}

func (h *DashboardHandler) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	provider := h.getProvider()
	if provider == nil {
		http.Error(w, "Identity provider is initializing", http.StatusServiceUnavailable)
		return
	}
	state, err := oauth.GenerateState()
	if err != nil {
		http.Error(w, "Failed to start login", http.StatusInternalServerError)
		return
	}
	verifier := oauth2.GenerateVerifier()
	transaction, err := h.jwtManager.CreateDashboardLoginToken(state, verifier, dashboardLoginTTL)
	if err != nil {
		http.Error(w, "Failed to start login", http.StatusInternalServerError)
		return
	}
	h.setCookie(w, dashboardLoginCookie, transaction, time.Now().Add(dashboardLoginTTL))
	config := *provider.OAuth2Config
	config.RedirectURL = h.baseURL + "/dashboard/callback"
	config.Scopes = slices.DeleteFunc(append([]string(nil), config.Scopes...), func(scope string) bool { return scope == "offline_access" })
	http.Redirect(w, r, config.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier)), http.StatusFound)
}

func (h *DashboardHandler) handleCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cookie, err := r.Cookie(dashboardLoginCookie)
	if err != nil {
		http.Error(w, "Login session expired", http.StatusBadRequest)
		return
	}
	transaction, err := h.jwtManager.ValidateDashboardLoginToken(cookie.Value)
	if err != nil || subtle.ConstantTimeCompare([]byte(transaction.State), []byte(r.URL.Query().Get("state"))) != 1 {
		http.Error(w, "Invalid login state", http.StatusBadRequest)
		return
	}
	provider := h.getProvider()
	if provider == nil {
		http.Error(w, "Identity provider is initializing", http.StatusServiceUnavailable)
		return
	}
	config := *provider.OAuth2Config
	config.RedirectURL = h.baseURL + "/dashboard/callback"
	config.Scopes = slices.DeleteFunc(append([]string(nil), config.Scopes...), func(scope string) bool { return scope == "offline_access" })
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	token, err := config.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(transaction.Verifier))
	if err != nil {
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}
	claims, verified, err := VerifyAndExtractClaims(ctx, provider, rawIDToken)
	if err != nil || claims.Email == "" || !groupsAllowed(claims.Groups, h.allowedGroups) {
		http.Error(w, "Authentication failed", http.StatusForbidden)
		return
	}
	ttl := dashboardSessionTTL
	if remaining := time.Until(verified.Expiry); remaining < ttl {
		ttl = remaining
	}
	sessionToken, err := h.jwtManager.CreateDashboardSessionToken(claims.Email, claims.Sub, verified.Issuer, claims.Groups, ttl)
	if err != nil {
		http.Error(w, "Failed to create dashboard session", http.StatusInternalServerError)
		return
	}
	h.clearCookie(w, dashboardLoginCookie)
	h.setCookie(w, dashboardCookie, sessionToken, time.Now().Add(ttl))
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func (h *DashboardHandler) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	claims, ok := h.dashboardClaims(r)
	if !ok || !h.validCSRF(r, claims) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	h.clearCookie(w, dashboardCookie)
	http.Redirect(w, r, "/dashboard/login", http.StatusSeeOther)
}

func (h *DashboardHandler) requireSession(next func(http.ResponseWriter, *http.Request, *jwt.DashboardSessionToken)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := h.dashboardClaims(r)
		if !ok {
			http.Redirect(w, r, "/dashboard/login", http.StatusSeeOther)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		next(w, r, claims)
	}
}

func (h *DashboardHandler) dashboardClaims(r *http.Request) (*jwt.DashboardSessionToken, bool) {
	cookie, err := r.Cookie(dashboardCookie)
	if err != nil {
		return nil, false
	}
	claims, err := h.jwtManager.ValidateDashboardSessionToken(cookie.Value)
	return claims, err == nil
}

func (h *DashboardHandler) handleOverview(w http.ResponseWriter, r *http.Request, claims *jwt.DashboardSessionToken) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	admin := (&CallerClaims{Email: claims.Email, Groups: claims.Groups}).isAdmin(h.adminGroups)
	var sessionsList []SessionInfo
	var ownedSessionIDs []string
	var rawSessions []v1alpha1.OAuthSession
	var err error
	if admin {
		rawSessions, err = h.sessions.ListAll(ctx)
	} else {
		rawSessions, err = h.sessions.GetByUser(ctx, claims.Email)
	}
	if err != nil {
		h.renderError(w, http.StatusServiceUnavailable, "Sessions are temporarily unavailable")
		return
	}
	for _, item := range rawSessions {
		if !admin && item.Status.Email == "" {
			continue
		}
		if !admin && !dashboardOwnsSession(claims, &item) {
			continue
		}
		sessionsList = append(sessionsList, sessionInfo(item))
		if !admin {
			ownedSessionIDs = append(ownedSessionIDs, item.Spec.SessionID)
		}
	}
	activeSessions := 0
	for _, item := range sessionsList {
		if item.Phase == string(v1alpha1.SessionActive) {
			activeSessions++
		}
	}
	sort.Slice(sessionsList, func(i, j int) bool { return sessionsList[i].CreatedAt.After(sessionsList[j].CreatedAt) })
	var metrics audit.RequestMetrics
	if admin {
		metrics, err = h.requests.GlobalMetrics(ctx, h.clusterName, time.Now().Add(-24*time.Hour))
	} else {
		metrics, err = h.requests.SessionsMetrics(ctx, h.clusterName, ownedSessionIDs, time.Now().Add(-24*time.Hour))
	}
	if err != nil {
		h.renderError(w, http.StatusServiceUnavailable, "Request metrics are temporarily unavailable")
		return
	}
	h.render(w, dashboardView{
		Title: "Sessions", Cluster: h.clusterName, Email: claims.Email, Admin: admin,
		CSRF: claims.CSRFToken, Sessions: sessionsList, ActiveSessions: activeSessions, Metrics: metrics,
	})
}

func (h *DashboardHandler) handleSession(w http.ResponseWriter, r *http.Request, claims *jwt.DashboardSessionToken) {
	sessionID, err := url.PathUnescape(strings.TrimPrefix(r.URL.Path, "/dashboard/sessions/"))
	if err != nil || sessionID == "" {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	oauthSession, err := h.sessions.Get(ctx, sessionID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	admin := (&CallerClaims{Email: claims.Email, Groups: claims.Groups}).isAdmin(h.adminGroups)
	if !admin && !dashboardOwnsSession(claims, oauthSession) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	if page > 100 {
		http.Error(w, "Page out of range", http.StatusBadRequest)
		return
	}
	events, err := h.requests.ListSession(ctx, h.clusterName, sessionID, 100, (page-1)*100)
	if err != nil {
		h.renderError(w, http.StatusServiceUnavailable, "Request history is temporarily unavailable")
		return
	}
	metrics, err := h.requests.SessionMetrics(ctx, h.clusterName, sessionID, time.Now().Add(-30*24*time.Hour))
	if err != nil {
		h.renderError(w, http.StatusServiceUnavailable, "Request metrics are temporarily unavailable")
		return
	}
	h.render(w, dashboardView{
		Title: "Session detail", Cluster: h.clusterName, Email: claims.Email, Admin: admin,
		CSRF: claims.CSRFToken, Detail: ptrTo(sessionInfo(*oauthSession)), Events: events,
		Metrics: metrics, ActiveSessions: boolInt(oauthSession.Status.Phase == v1alpha1.SessionActive),
		Page: page, PreviousPage: page - 1, NextPage: page + 1, HasNext: len(events) == 100,
	})
}

func groupsAllowed(groups, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, group := range groups {
		if slices.Contains(allowed, group) {
			return true
		}
	}
	return false
}

func dashboardOwnsSession(claims *jwt.DashboardSessionToken, oauthSession *v1alpha1.OAuthSession) bool {
	return oauthSession.Status.Subject != "" && oauthSession.Status.Issuer != "" &&
		claims.Subject == oauthSession.Status.Subject && claims.Issuer == oauthSession.Status.Issuer
}

func (h *DashboardHandler) validCSRF(r *http.Request, claims *jwt.DashboardSessionToken) bool {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		return false
	}
	if err := r.ParseForm(); err != nil || subtle.ConstantTimeCompare([]byte(r.FormValue("csrf")), []byte(claims.CSRFToken)) != 1 {
		return false
	}
	if origin := r.Header.Get("Origin"); origin != "" && origin != h.baseURL {
		return false
	}
	return true
}

func (h *DashboardHandler) setCookie(w http.ResponseWriter, name, value string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/dashboard", Expires: expires, MaxAge: int(time.Until(expires).Seconds()), HttpOnly: true, Secure: h.secureCookie, SameSite: http.SameSiteLaxMode})
}

func (h *DashboardHandler) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Path: "/dashboard", MaxAge: -1, HttpOnly: true, Secure: h.secureCookie, SameSite: http.SameSiteLaxMode})
}

func sessionInfo(item v1alpha1.OAuthSession) SessionInfo {
	info := SessionInfo{SessionID: item.Spec.SessionID, UserID: item.Spec.UserID, Email: item.Status.Email, Username: item.Status.Username, Phase: string(item.Status.Phase), CreatedAt: item.Spec.CreatedAt.Time}
	if !item.Spec.LastUsed.IsZero() {
		info.LastUsed = item.Spec.LastUsed.Time
	}
	if item.Status.CompletedAt != nil {
		info.CompletedAt = item.Status.CompletedAt.Time
	}
	if item.Status.RevokedAt != nil {
		info.RevokedAt = item.Status.RevokedAt.Time
	}
	return info
}

type dashboardView struct {
	Title, Cluster, Email, CSRF  string
	Admin, HasNext               bool
	ActiveSessions               int
	Sessions                     []SessionInfo
	Detail                       *SessionInfo
	Events                       []audit.RequestEvent
	Metrics                      audit.RequestMetrics
	Page, PreviousPage, NextPage int
}

func (h *DashboardHandler) render(w http.ResponseWriter, view dashboardView) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := dashboardTemplate.Execute(w, view); err != nil {
		http.Error(w, "Failed to render dashboard", http.StatusInternalServerError)
	}
}

func (h *DashboardHandler) renderError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, "<!doctype html><title>kauth</title><h1>%s</h1>", template.HTMLEscapeString(message))
}

func ptrTo[T any](value T) *T { return &value }

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
