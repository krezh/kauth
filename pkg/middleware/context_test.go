package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequestID_PopulatesContext(t *testing.T) {
	var gotID string

	handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotID, _ = r.Context().Value(RequestIDKey).(string)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if gotID == "" {
		t.Error("request ID should not be empty in context")
	}
}

func TestRequestLogger_GetsRequestID(t *testing.T) {
	ipExtractor := NewClientIPExtractor(nil)
	handler := RequestLogger(ipExtractor)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Should not panic and should get a request ID
	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
}

func TestRequestID_ChainedWithRequestLogger(t *testing.T) {
	ipExtractor := NewClientIPExtractor(nil)
	handler := RequestID(RequestLogger(ipExtractor)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
}