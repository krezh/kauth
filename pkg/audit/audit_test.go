package audit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"kauth/pkg/middleware"
)

func TestLog_CallsGetClientIP(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Real-IP", "192.168.1.100")
	req.Header.Set("X-Forwarded-For", "10.0.0.1")
	req.RemoteAddr = "127.0.0.1:12345"

	ctx := context.Background()
	ctx = context.WithValue(ctx, middleware.RequestIDKey, "test-request-id")

	Log(ctx, req, "test_event")

	ip := middleware.GetClientIP(req)
	if ip != "192.168.1.100" {
		t.Errorf("expected X-Real-IP 192.168.1.100, got %s", ip)
	}
}
