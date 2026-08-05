package handlers

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"kauth/pkg/audit"
	"kauth/pkg/jwt"
	"kauth/pkg/session"
)

func TestDashboardSSE_PushesFragmentOnSessionEvent(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()

	sessionClient, err := session.NewClient(ctx, dsn, "sse-test-cluster")
	if err != nil {
		t.Fatalf("session.NewClient() error = %v", err)
	}
	t.Cleanup(func() { _ = sessionClient.Close(context.Background()) })

	requestStore, err := audit.NewPostgresStore(ctx, dsn, 16, time.Hour)
	if err != nil {
		t.Fatalf("audit.NewPostgresStore() error = %v", err)
	}
	t.Cleanup(func() { _ = requestStore.Close(context.Background()) })

	jwtManager, err := jwt.NewManager(make([]byte, 32), make([]byte, 32))
	if err != nil {
		t.Fatalf("jwt.NewManager() error = %v", err)
	}

	handler := NewDashboardHandler(jwtManager, sessionClient, requestStore, DashboardConfig{ClusterName: "sse-test-cluster"})
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	const sessionID = "sse-test-session"
	const subject, issuer, email = "sse-test-subject", "https://issuer.example", "sse-user@example.com"
	_ = sessionClient.Delete(ctx, sessionID) // idempotent re-run: clear any row left by a previous run
	if _, err := sessionClient.Create(ctx, sessionID, "verifier", email); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if err := sessionClient.UpdateStatus(ctx, sessionID, session.Status{
		Phase: session.PhaseActive, Email: email, Subject: subject, Issuer: issuer,
	}); err != nil {
		t.Fatalf("UpdateStatus() error = %v", err)
	}

	token, err := jwtManager.CreateDashboardSessionToken(email, subject, issuer, nil, time.Hour)
	if err != nil {
		t.Fatalf("CreateDashboardSessionToken() error = %v", err)
	}

	reqCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, server.URL+"/sse/dashboard?session="+sessionID, nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext() error = %v", err)
	}
	req.AddCookie(&http.Cookie{Name: dashboardCookieName(false), Value: token})

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	go func() {
		time.Sleep(300 * time.Millisecond) // let the SSE handler subscribe before the mutation fires
		_ = sessionClient.UpdateStatus(ctx, sessionID, session.Status{
			Phase: session.PhaseActive, Email: email, Subject: subject, Issuer: issuer,
		})
	}()

	reader := bufio.NewReader(resp.Body)
	deadline := time.Now().Add(8 * time.Second)
	var sawEvent bool
	for time.Now().Before(deadline) {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("reading SSE stream: %v", err)
		}
		if !strings.HasPrefix(line, "event: detail-stats") {
			continue
		}
		data, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("reading SSE data line: %v", err)
		}
		if !strings.Contains(data, `id="detail-stats"`) || !strings.Contains(data, email) {
			t.Fatalf("detail-stats payload = %q, want it to contain id=\"detail-stats\" and %q", data, email)
		}
		sawEvent = true
		break
	}
	if !sawEvent {
		t.Fatal("did not observe a detail-stats SSE event within the deadline")
	}
}
