package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWithoutCookies(t *testing.T) {
	request := httptest.NewRequest("GET", "/api/info", nil)
	request.Header.Set("Cookie", "kauth_dashboard=secret")
	filtered := withoutCookies(request)
	if filtered.Header.Get("Cookie") != "" {
		t.Fatalf("filtered Cookie = %q", filtered.Header.Get("Cookie"))
	}
	if request.Header.Get("Cookie") == "" {
		t.Fatal("withoutCookies mutated the original request")
	}
}

func TestRouteHandlerStripsCookiesFromAPISubsystems(t *testing.T) {
	for _, path := range []string{"/api/info", "/k8s/version"} {
		t.Run(path, func(t *testing.T) {
			var receivedCookie string
			recorder := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				receivedCookie = r.Header.Get("Cookie")
				w.WriteHeader(http.StatusNoContent)
			})
			handler := routeHandler(recorder, recorder)
			request := httptest.NewRequest(http.MethodGet, path, nil)
			request.Header.Set("Cookie", "__Host-kauth_dashboard=secret")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if receivedCookie != "" {
				t.Fatalf("handler received Cookie %q", receivedCookie)
			}
		})
	}
}

func TestValidateBaseURLRequiresHTTPS(t *testing.T) {
	if err := validateBaseURL("https://kauth.example.com", false); err != nil {
		t.Fatal(err)
	}
	if err := validateBaseURL("http://kauth.example.com", false); err == nil {
		t.Fatal("HTTP BASE_URL accepted without explicit opt-in")
	}
	if err := validateBaseURL("http://localhost:8080", true); err != nil {
		t.Fatalf("explicit development HTTP rejected: %v", err)
	}
}
