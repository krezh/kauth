package handlers

import (
	"context"
	"crypto/subtle"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"kauth/pkg/audit"
	"kauth/pkg/jwt"
	"kauth/pkg/session"
)

const (
	dashboardCookie      = "kauth_dashboard"
	dashboardLoginCookie = "kauth_dashboard_login"
	dashboardLoginTTL    = 10 * time.Minute
	dashboardSessionTTL  = 15 * time.Minute
)

type DashboardHandler struct {
	jwtManager   *jwt.Manager
	sessions     *session.Client
	requests     audit.RequestStore
	baseURL      string
	clusterName  string
	adminGroups  []string
	secureCookie bool
	static       http.Handler
}

type DashboardConfig struct {
	BaseURL     string
	ClusterName string
	AdminGroups []string
}

func NewDashboardHandler(jwtManager *jwt.Manager, sessions *session.Client, requests audit.RequestStore, config DashboardConfig) *DashboardHandler {
	return &DashboardHandler{
		jwtManager: jwtManager, sessions: sessions, requests: requests,
		baseURL: config.BaseURL, clusterName: config.ClusterName,
		adminGroups:  config.AdminGroups,
		secureCookie: strings.HasPrefix(config.BaseURL, "https://"),
		static:       newStaticHandler(),
	}
}

func (h *DashboardHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/logout":
		h.handleLogout(w, r)
	case "/":
		h.requireSession(h.handleOverview)(w, r)
	case "/sse/dashboard":
		h.handleDashboardSSE(w, r)
	default:
		if strings.HasPrefix(r.URL.Path, "/static/") {
			h.static.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/sessions/") {
			h.requireSession(h.handleSession)(w, r)
			return
		}
		http.NotFound(w, r)
	}
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
	h.clearCookie(w, dashboardCookieName(h.secureCookie))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (h *DashboardHandler) requireSession(next func(http.ResponseWriter, *http.Request, *jwt.DashboardSessionToken)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := h.dashboardClaims(r)
		if !ok {
			h.renderSignIn(w)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		next(w, r, claims)
	}
}

func (h *DashboardHandler) renderSignIn(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = fmt.Fprint(w, `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>kauth</title><style>body{margin:0;background:#f4f1e9;color:#20231f;font:16px system-ui,sans-serif;min-height:100vh;display:grid;place-items:center}.card{width:min(420px,calc(100% - 48px));border:1px solid #20231f;background:#fffdf7;padding:40px;box-shadow:8px 8px 0 #20231f}.mark{font:700 28px ui-monospace,monospace;margin:0 0 32px}.card h1{font-size:32px;line-height:1.1;margin:0 0 12px}.card p{color:#60655e;line-height:1.6;margin:0 0 28px}.button{display:inline-block;background:#20231f;color:#fff;text-decoration:none;padding:12px 18px;font-weight:700}.button:focus,.button:hover{background:#3d4938}</style></head><body><main class="card"><div class="mark">kauth</div><h1>Kubernetes access</h1><p>Sign in to view your sessions and request history.</p><a class="button" href="/login">Sign in</a></main></body></html>`)
}

func (h *DashboardHandler) dashboardClaims(r *http.Request) (*jwt.DashboardSessionToken, bool) {
	cookie, err := r.Cookie(dashboardCookieName(h.secureCookie))
	if err != nil {
		return nil, false
	}
	claims, err := h.jwtManager.ValidateDashboardSessionToken(cookie.Value)
	return claims, err == nil
}

// overviewData is the admin/owner-scoped session listing shared by the full page and its SSE fragment.
type overviewData struct {
	Admin          bool
	Sessions       []SessionInfo
	OwnedIDs       []string
	ActiveSessions int
}

func (h *DashboardHandler) loadOverview(ctx context.Context, claims *jwt.DashboardSessionToken) (overviewData, error) {
	var data overviewData
	data.Admin = (&CallerClaims{Email: claims.Email, Groups: claims.Groups}).isAdmin(h.adminGroups)
	var rawSessions []session.Session
	var err error
	if data.Admin {
		rawSessions, err = h.sessions.ListAll(ctx)
	} else {
		rawSessions, err = h.sessions.GetByUser(ctx, claims.Email)
	}
	if err != nil {
		return overviewData{}, err
	}
	for _, item := range rawSessions {
		if !data.Admin && item.Email == "" {
			continue
		}
		if !data.Admin && !dashboardOwnsSession(claims, &item) {
			continue
		}
		data.Sessions = append(data.Sessions, sessionInfo(item))
		if !data.Admin {
			data.OwnedIDs = append(data.OwnedIDs, item.SessionID)
		}
		if item.Phase == session.PhaseActive {
			data.ActiveSessions++
		}
	}
	sort.Slice(data.Sessions, func(i, j int) bool { return data.Sessions[i].CreatedAt.After(data.Sessions[j].CreatedAt) })
	return data, nil
}

func (h *DashboardHandler) loadOverviewMetrics(ctx context.Context, data overviewData) (audit.RequestMetrics, error) {
	if data.Admin {
		return h.requests.GlobalMetrics(ctx, h.clusterName, time.Now().Add(-24*time.Hour))
	}
	return h.requests.SessionsMetrics(ctx, h.clusterName, data.OwnedIDs, time.Now().Add(-24*time.Hour))
}

func (h *DashboardHandler) handleOverview(w http.ResponseWriter, r *http.Request, claims *jwt.DashboardSessionToken) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	data, err := h.loadOverview(ctx, claims)
	if err != nil {
		h.renderError(w, http.StatusServiceUnavailable, "Sessions are temporarily unavailable")
		return
	}
	metrics, err := h.loadOverviewMetrics(ctx, data)
	if err != nil {
		h.renderError(w, http.StatusServiceUnavailable, "Request metrics are temporarily unavailable")
		return
	}
	h.render(w, dashboardView{
		Title: "Sessions", Cluster: h.clusterName, Email: claims.Email, Admin: data.Admin,
		CSRF: claims.CSRFToken, Sessions: data.Sessions, ActiveSessions: data.ActiveSessions, Metrics: metrics,
	})
}

func (h *DashboardHandler) handleSession(w http.ResponseWriter, r *http.Request, claims *jwt.DashboardSessionToken) {
	sessionID, err := url.PathUnescape(strings.TrimPrefix(r.URL.Path, "/sessions/"))
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
		Metrics: metrics, ActiveSessions: boolInt(oauthSession.Phase == session.PhaseActive),
		Page: page, PreviousPage: page - 1, NextPage: page + 1, HasNext: len(events) == 100,
	})
}

// dashboardPushInterval coalesces bursts of hub events and sets how often the session cookie is re-checked.
const dashboardPushInterval = 2 * time.Second

func (h *DashboardHandler) handleDashboardSSE(w http.ResponseWriter, r *http.Request) {
	claims, ok := h.dashboardClaims(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}
	sessionID := r.URL.Query().Get("session")
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}

	if sessionID != "" {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		oauthSession, err := h.sessions.Get(ctx, sessionID)
		cancel()
		if err != nil {
			http.NotFound(w, r)
			return
		}
		admin := (&CallerClaims{Email: claims.Email, Groups: claims.Groups}).isAdmin(h.adminGroups)
		if !admin && !dashboardOwnsSession(claims, oauthSession) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
	}

	sessionEvents, unsubscribeSessions := h.sessions.Subscribe()
	defer unsubscribeSessions()
	auditEvents, unsubscribeAudit := h.requests.Subscribe()
	defer unsubscribeAudit()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ticker := time.NewTicker(dashboardPushInterval)
	defer ticker.Stop()

	var dirty bool
	for {
		select {
		case ev := <-sessionEvents:
			if ev.Cluster != h.clusterName {
				continue
			}
			dirty = true
		case ev := <-auditEvents:
			if ev.Cluster != h.clusterName {
				continue
			}
			dirty = true
		case <-ticker.C:
			if _, ok := h.dashboardClaims(r); !ok {
				return
			}
			if !dirty {
				_, _ = fmt.Fprintf(w, ": keepalive\n\n")
				flusher.Flush()
				continue
			}
			// keep dirty set when the push failed so the next tick retries
			dirty = !h.pushDashboardFragments(r.Context(), w, flusher, claims, sessionID, page)
		case <-r.Context().Done():
			return
		}
	}
}

// pushDashboardFragments reports whether it wrote the fragments for this stream.
func (h *DashboardHandler) pushDashboardFragments(parent context.Context, w http.ResponseWriter, flusher http.Flusher, claims *jwt.DashboardSessionToken, sessionID string, page int) bool {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()

	if sessionID == "" {
		data, err := h.loadOverview(ctx, claims)
		if err != nil {
			return false
		}
		metrics, err := h.loadOverviewMetrics(ctx, data)
		if err != nil {
			return false
		}
		view := dashboardView{Sessions: data.Sessions, ActiveSessions: data.ActiveSessions, Metrics: metrics}
		h.writeFragment(w, flusher, "stat-strip", view)
		h.writeFragment(w, flusher, "sessions-tbody", view)
		return true
	}

	admin := (&CallerClaims{Email: claims.Email, Groups: claims.Groups}).isAdmin(h.adminGroups)
	oauthSession, err := h.sessions.Get(ctx, sessionID)
	if err != nil {
		return false
	}
	if !admin && !dashboardOwnsSession(claims, oauthSession) {
		return true
	}
	metrics, err := h.requests.SessionMetrics(ctx, h.clusterName, sessionID, time.Now().Add(-30*24*time.Hour))
	if err != nil {
		return false
	}
	view := dashboardView{
		Detail: ptrTo(sessionInfo(*oauthSession)), Metrics: metrics,
		ActiveSessions: boolInt(oauthSession.Phase == session.PhaseActive),
	}
	h.writeFragment(w, flusher, "stat-strip", view)
	h.writeFragment(w, flusher, "detail-stats", view)
	if page == 1 {
		events, err := h.requests.ListSession(ctx, h.clusterName, sessionID, 100, 0)
		if err != nil {
			return false
		}
		view.Events = events
		h.writeFragment(w, flusher, "events-tbody", view)
	}
	return true
}

func (h *DashboardHandler) writeFragment(w http.ResponseWriter, flusher http.Flusher, name string, view dashboardView) {
	var buf strings.Builder
	if err := dashboardTemplate.ExecuteTemplate(&buf, name, view); err != nil {
		return
	}
	_, _ = fmt.Fprintf(w, "event: %s\n%s\n", name, sseData(buf.String()))
	flusher.Flush()
}

// sseData frames payload as SSE data lines. Rendered values (e.g. request paths) can
// contain newlines, which would otherwise split or terminate the event.
func sseData(payload string) string {
	var b strings.Builder
	for line := range strings.SplitSeq(strings.ReplaceAll(payload, "\r\n", "\n"), "\n") {
		b.WriteString("data: ")
		b.WriteString(strings.ReplaceAll(line, "\r", ""))
		b.WriteString("\n")
	}
	return b.String()
}

func dashboardOwnsSession(claims *jwt.DashboardSessionToken, oauthSession *session.Session) bool {
	return oauthSession.Subject != "" && oauthSession.Issuer != "" &&
		claims.Subject == oauthSession.Subject && claims.Issuer == oauthSession.Issuer
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

func (h *DashboardHandler) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Path: "/", MaxAge: -1, HttpOnly: true, Secure: h.secureCookie, SameSite: http.SameSiteLaxMode})
}

func dashboardCookieName(secure bool) string {
	if secure {
		return "__Host-" + dashboardCookie
	}
	return dashboardCookie
}

func dashboardLoginCookieName(secure bool) string {
	if secure {
		return "__Host-" + dashboardLoginCookie
	}
	return dashboardLoginCookie
}

func dashboardLoginCookiePath(secure bool) string {
	if secure {
		return "/"
	}
	return "/callback"
}

func sessionInfo(item session.Session) SessionInfo {
	info := SessionInfo{SessionID: item.SessionID, UserID: item.UserID, Email: item.Email, Username: item.Username, Phase: string(item.Phase), CreatedAt: item.CreatedAt}
	if !item.LastUsed.IsZero() {
		info.LastUsed = item.LastUsed
	}
	if item.CompletedAt != nil {
		info.CompletedAt = *item.CompletedAt
	}
	if item.RevokedAt != nil {
		info.RevokedAt = *item.RevokedAt
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
