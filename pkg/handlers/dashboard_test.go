package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

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

func TestAnonymousDashboardDoesNotStartLogin(t *testing.T) {
	handler := &DashboardHandler{}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Sign in") {
		t.Fatalf("anonymous dashboard = %d: %s", response.Code, response.Body.String())
	}
}
