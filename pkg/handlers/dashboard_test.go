package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"kauth/pkg/audit"
	"kauth/pkg/jwt"
	"kauth/pkg/session"
)

func TestDashboardCSRF(t *testing.T) {
	handler := &DashboardHandler{baseURL: "https://kauth.example.com"}
	claims := &jwt.DashboardSessionToken{CSRFToken: "expected"}

	tests := []struct {
		name        string
		contentType string
		origin      string
		token       string
		want        bool
	}{
		{name: "valid", contentType: "application/x-www-form-urlencoded", origin: handler.baseURL, token: "expected", want: true},
		{name: "missing token", contentType: "application/x-www-form-urlencoded", origin: handler.baseURL},
		{name: "wrong origin", contentType: "application/x-www-form-urlencoded", origin: "https://attacker.example", token: "expected"},
		{name: "wrong content type", contentType: "text/plain", origin: handler.baseURL, token: "expected"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			form := url.Values{"csrf": []string{tt.token}}
			req := httptest.NewRequest(http.MethodPost, "/logout", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", tt.contentType)
			req.Header.Set("Origin", tt.origin)
			if got := handler.validCSRF(req, claims); got != tt.want {
				t.Fatalf("validCSRF() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDashboardOwnsSession(t *testing.T) {
	claims := &jwt.DashboardSessionToken{Email: "reused@example.com", Subject: "new-subject", Issuer: "https://issuer.example"}
	if dashboardOwnsSession(claims, &session.Session{
		Email: "reused@example.com", Subject: "old-subject", Issuer: "https://issuer.example",
	}) {
		t.Fatal("email reuse must not grant access to another OIDC subject")
	}
	if !dashboardOwnsSession(claims, &session.Session{
		Email: "reused@example.com", Subject: "new-subject", Issuer: "https://issuer.example",
	}) {
		t.Fatal("matching issuer and subject should grant access")
	}
	if dashboardOwnsSession(claims, &session.Session{Email: "reused@example.com"}) {
		t.Fatal("sessions without immutable ownership must not be accessible")
	}
}

func TestDashboardCookieScope(t *testing.T) {
	handler := &LoginHandler{secureCookie: true}
	response := httptest.NewRecorder()
	handler.setBrowserCookie(response, dashboardCookieName(true), "value", "/", time.Now().Add(time.Minute), http.SameSiteLaxMode)
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "__Host-kauth_dashboard" || cookies[0].Path != "/" || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteLaxMode {
		t.Fatalf("unexpected dashboard cookie: %#v", cookies)
	}

	response = httptest.NewRecorder()
	handler.setBrowserCookie(response, dashboardLoginCookieName(true), "value", dashboardLoginCookiePath(true), time.Now().Add(time.Minute), http.SameSiteLaxMode)
	if cookies := response.Result().Cookies(); len(cookies) != 1 || cookies[0].Name != "__Host-kauth_dashboard_login" || cookies[0].Path != "/" || !cookies[0].Secure || cookies[0].SameSite != http.SameSiteLaxMode {
		t.Fatalf("unexpected login binding cookie: %#v", cookies)
	}
	if dashboardLoginCookieName(false) != dashboardLoginCookie || dashboardLoginCookiePath(false) != "/callback" {
		t.Fatal("HTTP development cookie must remain unprefixed and callback-scoped")
	}
}

func TestFragmentTemplates(t *testing.T) {
	overview := dashboardView{
		Sessions:       []SessionInfo{{SessionID: "sess-1", Email: "user@example.com", Phase: "Active", CreatedAt: time.Now()}},
		ActiveSessions: 1,
		Metrics:        audit.RequestMetrics{Requests: 5, ClientErrors: 1},
	}
	for _, tt := range []struct {
		name     string
		template string
		view     dashboardView
		want     []string
	}{
		{"stat-strip", "stat-strip", overview, []string{`id="stat-strip"`, "5"}},
		{"sessions-tbody with rows", "sessions-tbody", overview, []string{`id="sessions-tbody"`, "sess-1", "user@example.com"}},
		{"sessions-tbody empty", "sessions-tbody", dashboardView{}, []string{`id="sessions-tbody"`, "No sessions found."}},
		{"detail-stats", "detail-stats", dashboardView{Detail: &SessionInfo{Email: "user@example.com", Phase: "Revoked"}}, []string{`id="detail-stats"`, "user@example.com", "Revoked"}},
		{"events-tbody with rows", "events-tbody", dashboardView{Events: []audit.RequestEvent{{Method: "GET", Path: "/x", StatusCode: 200}}}, []string{`id="events-tbody"`, "/x", "200"}},
		{"events-tbody empty", "events-tbody", dashboardView{}, []string{`id="events-tbody"`, "No API requests recorded for this session."}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var buf strings.Builder
			if err := dashboardTemplate.ExecuteTemplate(&buf, tt.template, tt.view); err != nil {
				t.Fatalf("ExecuteTemplate(%q) error = %v", tt.template, err)
			}
			for _, want := range tt.want {
				if !strings.Contains(buf.String(), want) {
					t.Errorf("ExecuteTemplate(%q) = %q, want substring %q", tt.template, buf.String(), want)
				}
			}
			if strings.Contains(buf.String(), "\n") {
				t.Errorf("ExecuteTemplate(%q) contains a raw newline, which breaks SSE data: framing", tt.template)
			}
		})
	}
}

func TestWriteFragmentFramesNewlinesInRenderedValues(t *testing.T) {
	handler := &DashboardHandler{}
	response := httptest.NewRecorder()
	handler.writeFragment(response, response, "events-tbody", dashboardView{
		Events: []audit.RequestEvent{{Method: "GET", Path: "/api/v1\n\nevent: injected\ndata: x", StatusCode: 200}},
	})

	body := response.Body.String()
	if strings.Count(body, "\n\n") != 1 || !strings.HasSuffix(body, "\n\n") {
		t.Fatalf("fragment = %q, want exactly one terminating blank line", body)
	}
	for _, line := range strings.Split(strings.TrimSuffix(body, "\n\n"), "\n") {
		if !strings.HasPrefix(line, "event: ") && !strings.HasPrefix(line, "data: ") {
			t.Fatalf("fragment line = %q, want an event: or data: field", line)
		}
	}
}

func TestAnonymousDashboardSSEReturns401NotSignInPage(t *testing.T) {
	handler := &DashboardHandler{}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/sse/dashboard", nil))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous /sse/dashboard status = %d, want 401 (a 200 sign-in page makes EventSource retry forever)", response.Code)
	}
}

func TestAnonymousDashboardDoesNotStartLogin(t *testing.T) {
	handler := &DashboardHandler{}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Sign in") {
		t.Fatalf("anonymous dashboard = %d: %s", response.Code, response.Body.String())
	}
}
