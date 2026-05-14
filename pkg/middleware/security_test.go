package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimiter_IPExtraction(t *testing.T) {
	rl := NewRateLimiter(10, 20, time.Minute, nil)
	handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name          string
		xRealIP       string
		xForwardedFor string
		remoteAddr    string
		expectedIP    string
	}{
		{
			name:          "X-Real-IP takes precedence",
			xRealIP:       "192.168.1.100",
			xForwardedFor: "10.0.0.1",
			remoteAddr:    "127.0.0.1:12345",
			expectedIP:    "192.168.1.100",
		},
		{
			name:          "X-Forwarded-For when no X-Real-IP",
			xRealIP:       "",
			xForwardedFor: "203.0.113.50, 10.0.0.1",
			remoteAddr:    "127.0.0.1:12345",
			expectedIP:    "203.0.113.50",
		},
		{
			name:          "X-Forwarded-For single IP",
			xRealIP:       "",
			xForwardedFor: "203.0.113.50",
			remoteAddr:    "127.0.0.1:12345",
			expectedIP:    "203.0.113.50",
		},
		{
			name:          "RemoteAddr fallback",
			xRealIP:       "",
			xForwardedFor: "",
			remoteAddr:    "192.168.1.1:8080",
			expectedIP:    "192.168.1.1",
		},
		{
			name:          "RemoteAddr without port",
			xRealIP:       "",
			xForwardedFor: "",
			remoteAddr:    "192.168.1.1",
			expectedIP:    "192.168.1.1",
		},
		{
			name:          "X-Forwarded-For with extra spaces",
			xRealIP:       "",
			xForwardedFor: "  203.0.113.50  ,  10.0.0.1  ",
			remoteAddr:    "127.0.0.1:12345",
			expectedIP:    "203.0.113.50",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.xRealIP != "" {
				req.Header.Set("X-Real-IP", tt.xRealIP)
			}
			if tt.xForwardedFor != "" {
				req.Header.Set("X-Forwarded-For", tt.xForwardedFor)
			}
			req.RemoteAddr = tt.remoteAddr

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Errorf("expected status 200, got %d", rr.Code)
			}
		})
	}
}

func TestRateLimiter_AllowsRequests(t *testing.T) {
	rl := NewRateLimiter(100, 100, time.Minute, nil)
	handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
}

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name          string
		xRealIP       string
		xForwardedFor string
		remoteAddr    string
		expectedIP    string
	}{
		{
			name:          "X-Real-IP takes precedence",
			xRealIP:       "192.168.1.100",
			xForwardedFor: "10.0.0.1",
			remoteAddr:    "127.0.0.1:12345",
			expectedIP:    "192.168.1.100",
		},
		{
			name:          "X-Forwarded-For when no X-Real-IP",
			xRealIP:       "",
			xForwardedFor: "203.0.113.50, 10.0.0.1",
			remoteAddr:    "127.0.0.1:12345",
			expectedIP:    "203.0.113.50",
		},
		{
			name:          "X-Forwarded-For single IP",
			xRealIP:       "",
			xForwardedFor: "203.0.113.50",
			remoteAddr:    "127.0.0.1:12345",
			expectedIP:    "203.0.113.50",
		},
		{
			name:          "RemoteAddr fallback with port",
			xRealIP:       "",
			xForwardedFor: "",
			remoteAddr:    "192.168.1.1:8080",
			expectedIP:    "192.168.1.1",
		},
		{
			name:          "RemoteAddr without port",
			xRealIP:       "",
			xForwardedFor: "",
			remoteAddr:    "192.168.1.1",
			expectedIP:    "192.168.1.1",
		},
		{
			name:          "X-Forwarded-For with extra spaces",
			xRealIP:       "",
			xForwardedFor: "  203.0.113.50  ,  10.0.0.1  ",
			remoteAddr:    "127.0.0.1:12345",
			expectedIP:    "203.0.113.50",
		},
		{
			name:          "IPv6 localhost",
			xRealIP:       "",
			xForwardedFor: "",
			remoteAddr:    "[::1]:8080",
			expectedIP:    "::1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.xRealIP != "" {
				req.Header.Set("X-Real-IP", tt.xRealIP)
			}
			if tt.xForwardedFor != "" {
				req.Header.Set("X-Forwarded-For", tt.xForwardedFor)
			}
			req.RemoteAddr = tt.remoteAddr

			got := GetClientIP(req)
			if got != tt.expectedIP {
				t.Errorf("GetClientIP() = %q, want %q", got, tt.expectedIP)
			}
		})
	}
}

func TestRateLimiter_BlocksWhenExceeded(t *testing.T) {
	rl := NewRateLimiter(1, 1, time.Minute, nil)
	handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("first request should pass, got %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("second request should be rate limited, got %d", rr.Code)
	}
}

func TestRateLimiter_XForwardedForExtractsFirstIP(t *testing.T) {
	rl := NewRateLimiter(1, 1, time.Minute, nil)
	handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.Header.Set("X-Forwarded-For", "192.168.1.1, 10.0.0.1")
	req1.RemoteAddr = "127.0.0.1:12345"

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req1)
	if rr.Code != http.StatusOK {
		t.Fatalf("first request should pass, got %d", rr.Code)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Header.Set("X-Forwarded-For", "192.168.1.2, 10.0.0.1")

	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req2)
	if rr.Code != http.StatusOK {
		t.Errorf("different first IP should have separate limit, got %d", rr.Code)
	}
}

func TestRateLimiter_TrustedProxyRespectsHeaders(t *testing.T) {
	rl := NewRateLimiter(1, 1, time.Minute, []string{"127.0.0.1/32"})
	handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.Header.Set("X-Forwarded-For", "192.168.1.1, 10.0.0.1")
	req1.RemoteAddr = "127.0.0.1:12345"

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req1)
	if rr.Code != http.StatusOK {
		t.Fatalf("first request should pass, got %d", rr.Code)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Header.Set("X-Forwarded-For", "192.168.1.1, 10.0.0.2")
	req2.RemoteAddr = "127.0.0.1:12345"

	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req2)
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("same client IP from trusted proxy should share limit, got %d", rr.Code)
	}
}

func TestRateLimiter_UntrustedProxyIgnoresHeaders(t *testing.T) {
	rl := NewRateLimiter(1, 1, time.Minute, []string{"10.0.0.0/8"})
	handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.Header.Set("X-Forwarded-For", "192.168.1.1")
	req1.RemoteAddr = "192.168.1.100:12345"

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req1)
	if rr.Code != http.StatusOK {
		t.Fatalf("first request should pass, got %d", rr.Code)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Header.Set("X-Forwarded-For", "10.0.0.1")
	req2.RemoteAddr = "192.168.1.100:12345"

	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req2)
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("untrusted proxy should fall back to RemoteAddr and share limit, got %d", rr.Code)
	}
}

func TestRateLimiter_TrustedProxyDifferentIPs(t *testing.T) {
	rl := NewRateLimiter(1, 1, time.Minute, []string{"127.0.0.1/32"})
	handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.Header.Set("X-Forwarded-For", "192.168.1.1")
	req1.RemoteAddr = "127.0.0.1:12345"

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req1)
	if rr.Code != http.StatusOK {
		t.Fatalf("first request should pass, got %d", rr.Code)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Header.Set("X-Forwarded-For", "192.168.1.2")
	req2.RemoteAddr = "127.0.0.1:12345"

	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req2)
	if rr.Code != http.StatusOK {
		t.Errorf("different IPs from trusted proxy should have separate limits, got %d", rr.Code)
	}
}
