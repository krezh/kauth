package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"kauth/pkg/jwt"
	"kauth/pkg/session"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type fakeSessionStore struct {
	session *session.Session
	err     error
	touched string
}

type blockingSessionStore struct {
	gets    atomic.Int32
	release chan struct{}
	session *session.Session
}

func (s *blockingSessionStore) Get(context.Context, string) (*session.Session, error) {
	s.gets.Add(1)
	<-s.release
	return s.session, nil
}

func (*blockingSessionStore) TouchLastUsed(context.Context, string, time.Duration) error { return nil }

func (f *fakeSessionStore) Get(_ context.Context, _ string) (*session.Session, error) {
	return f.session, f.err
}

func (f *fakeSessionStore) TouchLastUsed(_ context.Context, sessionID string, _ time.Duration) error {
	f.touched = sessionID
	return nil
}

func newTestJWTManager(t *testing.T) *jwt.Manager {
	t.Helper()
	manager, err := jwt.NewManager(make([]byte, 32), make([]byte, 32))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return manager
}

func newActiveSession(email string, groups ...string) *session.Session {
	return &session.Session{
		Phase:  session.PhaseActive,
		Email:  email,
		Groups: groups,
	}
}

func TestSessionAuthenticator(t *testing.T) {
	manager := newTestJWTManager(t)
	token, err := manager.CreateAPIToken("session-1", time.Hour)
	if err != nil {
		t.Fatalf("CreateAPIToken: %v", err)
	}

	tests := []struct {
		name        string
		token       string
		session     *session.Session
		wantErr     bool
		wantTouched bool
	}{
		{name: "active", token: token, session: newActiveSession("user@example.com", "developers"), wantTouched: true},
		{name: "recently active", token: token, session: func() *session.Session {
			sess := newActiveSession("user@example.com", "developers")
			sess.LastUsed = time.Now()
			return sess
		}()},
		{name: "revoked", token: token, session: &session.Session{Phase: session.PhaseRevoked, Email: "user@example.com"}, wantErr: true},
		{name: "invalid token", token: "invalid", session: newActiveSession("user@example.com"), wantErr: true},
		{name: "empty email", token: token, session: newActiveSession(""), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &fakeSessionStore{session: tt.session}
			authenticator := &SessionAuthenticator{jwtManager: manager, sessionClient: store}
			identity, err := authenticator.Authenticate(context.Background(), tt.token)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Authenticate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if identity.SessionID != "session-1" || identity.Username != "user@example.com" {
				t.Fatalf("identity = %#v", identity)
			}
			if (store.touched != "") != tt.wantTouched {
				t.Fatalf("touched session = %q, wantTouched %v", store.touched, tt.wantTouched)
			}
		})
	}
}

func TestSessionAuthenticatorCoalescesConcurrentLookups(t *testing.T) {
	manager := newTestJWTManager(t)
	token, err := manager.CreateAPIToken("session-1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	store := &blockingSessionStore{release: make(chan struct{}), session: newActiveSession("user@example.com")}
	authenticator := &SessionAuthenticator{jwtManager: manager, sessionClient: store}
	start := make(chan struct{})
	errors := make(chan error, 32)
	var wait sync.WaitGroup
	for range 32 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, err := authenticator.Authenticate(context.Background(), token)
			errors <- err
		}()
	}
	close(start)
	time.Sleep(50 * time.Millisecond)
	close(store.release)
	wait.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := store.gets.Load(); got != 1 {
		t.Fatalf("session lookups = %d, want 1", got)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestKubernetesProxyHandler(t *testing.T) {
	var upstreamRequest *http.Request
	var upstreamBody []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamRequest = r.Clone(r.Context())
		upstreamBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("proxied"))
	}))
	defer upstream.Close()

	manager := newTestJWTManager(t)
	token, err := manager.CreateAPIToken("session-1", time.Hour)
	if err != nil {
		t.Fatalf("CreateAPIToken: %v", err)
	}
	store := &fakeSessionStore{session: newActiveSession("user@example.com", "developers", "system:masters")}
	authenticator := &SessionAuthenticator{jwtManager: manager, sessionClient: store}
	transport := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		r.Header.Set("Authorization", "Bearer upstream-service-account")
		return http.DefaultTransport.RoundTrip(r)
	})
	handler := NewKubernetesProxyHandler(authenticator, mustParseURL(t, upstream.URL), transport)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/namespaces/default/pods?fieldSelector=metadata.name%3Ddemo", bytes.NewBufferString("request body"))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Cookie", "kauth_dashboard=secret")
	req.Header.Set("Impersonate-User", "attacker@example.com")
	req.Header.Add("Impersonate-Group", "system:masters")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated || rr.Body.String() != "proxied" {
		t.Fatalf("response = %d %q", rr.Code, rr.Body.String())
	}
	if upstreamRequest.Method != http.MethodPost || upstreamRequest.URL.RequestURI() != "/api/v1/namespaces/default/pods?fieldSelector=metadata.name%3Ddemo" {
		t.Fatalf("upstream request = %s %s", upstreamRequest.Method, upstreamRequest.URL.RequestURI())
	}
	if string(upstreamBody) != "request body" {
		t.Fatalf("upstream body = %q", upstreamBody)
	}
	if got := upstreamRequest.Header.Get("Authorization"); got != "Bearer upstream-service-account" {
		t.Fatalf("upstream Authorization = %q", got)
	}
	if got := upstreamRequest.Header.Get("Cookie"); got != "" {
		t.Fatalf("upstream Cookie = %q", got)
	}
	if got := upstreamRequest.Header.Get("Impersonate-User"); got != "user@example.com" {
		t.Fatalf("Impersonate-User = %q", got)
	}
	groups := upstreamRequest.Header.Values("Impersonate-Group")
	if !slices.Contains(groups, "developers") || !slices.Contains(groups, "system:authenticated") || slices.Contains(groups, "system:masters") {
		t.Fatalf("Impersonate-Group = %v", groups)
	}
}

func TestKubernetesProxyHandlerUnauthorized(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("upstream should not be called")
	}))
	defer upstream.Close()

	handler := NewKubernetesProxyHandler(
		&SessionAuthenticator{jwtManager: newTestJWTManager(t), sessionClient: &fakeSessionStore{}},
		mustParseURL(t, upstream.URL),
		http.DefaultTransport,
	)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api", nil))

	if rr.Code != http.StatusUnauthorized || rr.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Fatalf("response = %d, WWW-Authenticate = %q", rr.Code, rr.Header().Get("WWW-Authenticate"))
	}
	var status metav1.Status
	if err := json.Unmarshal(rr.Body.Bytes(), &status); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if status.Kind != "Status" || status.Reason != metav1.StatusReasonUnauthorized || status.Code != http.StatusUnauthorized {
		t.Fatalf("status = %#v", status)
	}
}

func mustParseURL(t *testing.T, rawURL string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}
	return parsed
}
