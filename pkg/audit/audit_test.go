package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"kauth/pkg/middleware"
)

type captureRequestStore struct {
	event RequestEvent
}

func (s *captureRequestStore) Record(event RequestEvent) bool {
	s.event = event
	return true
}

func (*captureRequestStore) ListSession(context.Context, string, string, int, int) ([]RequestEvent, error) {
	return nil, nil
}

func (*captureRequestStore) SessionMetrics(context.Context, string, string, time.Time) (RequestMetrics, error) {
	return RequestMetrics{}, nil
}

func (*captureRequestStore) SessionsMetrics(context.Context, string, []string, time.Time) (RequestMetrics, error) {
	return RequestMetrics{}, nil
}

func (*captureRequestStore) GlobalMetrics(context.Context, string, time.Time) (RequestMetrics, error) {
	return RequestMetrics{}, nil
}

func (*captureRequestStore) Close(context.Context) error { return nil }

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

func TestKubernetesRequest(t *testing.T) {
	var output bytes.Buffer
	original := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	t.Cleanup(func() { slog.SetDefault(original) })

	req := httptest.NewRequest(http.MethodGet, "/api/v1/pods", nil)
	ctx := context.WithValue(req.Context(), middleware.RequestIDKey, "request-1")
	store := &captureRequestStore{}
	SetRequestStore(store, "production")
	t.Cleanup(func() { SetRequestStore(nil, "") })
	KubernetesRequest(ctx, req, "session-1", "user@example.com", []string{"developers"}, true, http.StatusOK, 123, 25*time.Millisecond)

	var event map[string]any
	if err := json.Unmarshal(output.Bytes(), &event); err != nil {
		t.Fatalf("decode audit log: %v", err)
	}
	for key, want := range map[string]any{
		"audit_event":   EventKubernetesRequest,
		"request_id":    "request-1",
		"session_id":    "session-1",
		"user":          "user@example.com",
		"method":        http.MethodGet,
		"path":          "/api/v1/pods",
		"authenticated": true,
	} {
		if got := event[key]; got != want {
			t.Errorf("%s = %#v, want %#v", key, got, want)
		}
	}
	if store.event.Cluster != "production" || store.event.SessionID != "session-1" || store.event.Path != "/api/v1/pods" || store.event.RequestID != "request-1" {
		t.Fatalf("stored event = %#v", store.event)
	}
}
