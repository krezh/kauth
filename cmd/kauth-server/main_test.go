package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReadinessHandlerTracksProviderInitialization(t *testing.T) {
	ready := make(chan struct{})
	handler := readinessHandler(ready)

	response := httptest.NewRecorder()
	handler(response, httptest.NewRequest(http.MethodGet, "/ready", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status before initialization = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}

	close(ready)
	response = httptest.NewRecorder()
	handler(response, httptest.NewRequest(http.MethodGet, "/ready", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status after initialization = %d, want %d", response.Code, http.StatusOK)
	}
}
