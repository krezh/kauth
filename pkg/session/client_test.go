package session

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestClient_Create(t *testing.T) {
	client := testClient(t)
	ctx := context.Background()

	s, err := client.Create(ctx, "test-state-123", "test-verifier", "user@example.com")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if s.SessionID != "test-state-123" {
		t.Errorf("SessionID = %q, want %q", s.SessionID, "test-state-123")
	}
	if s.Verifier != "test-verifier" {
		t.Errorf("Verifier = %q, want %q", s.Verifier, "test-verifier")
	}
	if s.UserID != "user@example.com" {
		t.Errorf("UserID = %q, want %q", s.UserID, "user@example.com")
	}
	if s.Phase != PhasePending {
		t.Errorf("Phase = %q, want %q", s.Phase, PhasePending)
	}
	if s.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set")
	}
}

func TestClient_Create_EmptyUserID(t *testing.T) {
	client := testClient(t)
	ctx := context.Background()

	s, err := client.Create(ctx, "no-user-id", "verifier", "")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if s.UserID != "" {
		t.Errorf("UserID = %q, want empty", s.UserID)
	}
}

func TestClient_Get(t *testing.T) {
	client := testClient(t)
	ctx := context.Background()

	created, err := client.Create(ctx, "test-state-456", "verifier", "user@example.com")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	got, err := client.Get(ctx, "test-state-456")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got.SessionID != created.SessionID {
		t.Errorf("SessionID = %q, want %q", got.SessionID, created.SessionID)
	}
	if got.UserID != created.UserID {
		t.Errorf("UserID = %q, want %q", got.UserID, created.UserID)
	}
	if got.Verifier != created.Verifier {
		t.Errorf("Verifier = %q, want %q", got.Verifier, created.Verifier)
	}
}

func TestClient_Get_NotFound(t *testing.T) {
	client := testClient(t)
	ctx := context.Background()

	_, err := client.Get(ctx, "nonexistent-state")
	if !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("Get() error = %v, want ErrSessionNotFound", err)
	}
}

func TestClient_UpdateStatus(t *testing.T) {
	client := testClient(t)
	ctx := context.Background()

	if _, err := client.Create(ctx, "test-state-789", "verifier", "user@example.com"); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	err := client.UpdateStatus(ctx, "test-state-789", Status{
		Phase:        PhaseActive,
		Email:        "user@example.com",
		Username:     "testuser",
		RefreshToken: "encrypted-refresh-token",
	})
	if err != nil {
		t.Fatalf("UpdateStatus() error = %v", err)
	}

	got, err := client.Get(ctx, "test-state-789")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got.Phase != PhaseActive {
		t.Errorf("Phase = %q, want %q", got.Phase, PhaseActive)
	}
	if got.Email != "user@example.com" {
		t.Errorf("Email = %q, want %q", got.Email, "user@example.com")
	}
	if got.Username != "testuser" {
		t.Errorf("Username = %q, want %q", got.Username, "testuser")
	}
	if got.RefreshToken != "encrypted-refresh-token" {
		t.Errorf("RefreshToken = %q, want %q", got.RefreshToken, "encrypted-refresh-token")
	}
	if got.CompletedAt == nil {
		t.Error("CompletedAt should be set when phase is Active")
	}
}

func TestClient_UpdateStatus_PendingNoCompletedAt(t *testing.T) {
	client := testClient(t)
	ctx := context.Background()

	if _, err := client.Create(ctx, "pending-test", "verifier", "user@example.com"); err != nil {
		t.Fatal(err)
	}

	if err := client.UpdateStatus(ctx, "pending-test", Status{
		Phase: PhasePending,
		Error: "some error",
	}); err != nil {
		t.Fatalf("UpdateStatus() error = %v", err)
	}

	got, _ := client.Get(ctx, "pending-test")
	if got.CompletedAt != nil {
		t.Error("CompletedAt should NOT be set when phase is Pending")
	}
}

func TestClient_UpdateStatus_PreservesCompletedAtAcrossActiveUpdates(t *testing.T) {
	client := testClient(t)
	ctx := context.Background()

	if _, err := client.Create(ctx, "completedat-test", "verifier", "user@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := client.UpdateStatus(ctx, "completedat-test", Status{Phase: PhaseActive}); err != nil {
		t.Fatal(err)
	}
	first, _ := client.Get(ctx, "completedat-test")
	if first.CompletedAt == nil {
		t.Fatal("CompletedAt should be set on first Active transition")
	}

	if err := client.UpdateStatus(ctx, "completedat-test", Status{Phase: PhaseActive, Username: "renamed"}); err != nil {
		t.Fatal(err)
	}
	second, _ := client.Get(ctx, "completedat-test")
	if second.CompletedAt == nil || !second.CompletedAt.Equal(*first.CompletedAt) {
		t.Errorf("CompletedAt changed across a subsequent Active update: first=%v second=%v", first.CompletedAt, second.CompletedAt)
	}
}

func TestClient_UpdateStatus_CannotReactivateTerminalSession(t *testing.T) {
	client := testClient(t)
	ctx := context.Background()

	if _, err := client.Create(ctx, "terminal-test", "verifier", "user@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := client.UpdateStatus(ctx, "terminal-test", Status{Phase: PhaseRevoked}); err != nil {
		t.Fatal(err)
	}

	err := client.UpdateStatus(ctx, "terminal-test", Status{Phase: PhaseActive})
	if err == nil {
		t.Fatal("UpdateStatus() should reject reactivating a Revoked session")
	}

	got, _ := client.Get(ctx, "terminal-test")
	if got.Phase != PhaseRevoked {
		t.Errorf("Phase changed despite rejected update: %q", got.Phase)
	}
}

func TestClient_UpdateStatus_NotFound(t *testing.T) {
	client := testClient(t)
	ctx := context.Background()

	err := client.UpdateStatus(ctx, "does-not-exist", Status{Phase: PhaseActive})
	if !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("UpdateStatus() error = %v, want wrapped ErrSessionNotFound", err)
	}
}

func TestClient_ClaimLoginIsSingleUse(t *testing.T) {
	client := testClient(t)
	ctx := context.Background()

	if _, err := client.Create(ctx, "claim-test", "verifier", ""); err != nil {
		t.Fatal(err)
	}
	if err := client.ClaimLogin(ctx, "claim-test"); err != nil {
		t.Fatal(err)
	}
	if err := client.UpdateStatus(ctx, "claim-test", Status{
		Phase: PhaseFailed, Error: "token exchange failed",
	}); err != nil {
		t.Fatal(err)
	}
	if err := client.ClaimLogin(ctx, "claim-test"); !errors.Is(err, ErrLoginAlreadyClaimed) {
		t.Fatalf("ClaimLogin() after failure error = %v, want ErrLoginAlreadyClaimed", err)
	}
}

func TestClient_ClaimLoginNotFound(t *testing.T) {
	client := testClient(t)
	ctx := context.Background()

	err := client.ClaimLogin(ctx, "does-not-exist")
	if !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("ClaimLogin() error = %v, want wrapped ErrSessionNotFound", err)
	}
}

func TestClient_ClaimLoginConcurrentExactlyOneWins(t *testing.T) {
	client := testClient(t)
	ctx := context.Background()

	if _, err := client.Create(ctx, "concurrent-claim-test", "verifier", ""); err != nil {
		t.Fatal(err)
	}

	const attempts = 10
	results := make(chan error, attempts)
	var start sync.WaitGroup
	start.Add(1)
	for i := 0; i < attempts; i++ {
		go func() {
			start.Wait()
			results <- client.ClaimLogin(ctx, "concurrent-claim-test")
		}()
	}
	start.Done()

	wins, losses := 0, 0
	for i := 0; i < attempts; i++ {
		err := <-results
		switch {
		case err == nil:
			wins++
		case errors.Is(err, ErrLoginAlreadyClaimed):
			losses++
		default:
			t.Fatalf("unexpected ClaimLogin() error: %v", err)
		}
	}
	if wins != 1 {
		t.Errorf("wins = %d, want exactly 1 (losses = %d)", wins, losses)
	}
	if wins+losses != attempts {
		t.Errorf("wins+losses = %d, want %d", wins+losses, attempts)
	}
}

func TestClient_RotateRefreshTokenRejectsReplay(t *testing.T) {
	client := testClient(t)
	ctx := context.Background()

	if _, err := client.Create(ctx, "rotation-test", "verifier", "user@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := client.UpdateStatus(ctx, "rotation-test", Status{
		Phase: PhaseActive, RefreshToken: "current", APIToken: "api-token",
	}); err != nil {
		t.Fatal(err)
	}

	current, err := client.Get(ctx, "rotation-test")
	if err != nil {
		t.Fatal(err)
	}

	if err := client.RotateRefreshToken(ctx, "rotation-test", current.TokenRotation+1, Status{
		Phase: PhaseActive, RefreshToken: "next",
	}); !errors.Is(err, ErrRefreshTokenReplayed) {
		t.Fatalf("RotateRefreshToken() with a stale rotation error = %v, want ErrRefreshTokenReplayed", err)
	}

	if err := client.RotateRefreshToken(ctx, "rotation-test", current.TokenRotation, Status{
		Phase: PhaseActive, RefreshToken: "next",
	}); err != nil {
		t.Fatal(err)
	}

	// The counter advanced, so replaying the same rotation loses the compare-and-set.
	if err := client.RotateRefreshToken(ctx, "rotation-test", current.TokenRotation, Status{
		Phase: PhaseActive, RefreshToken: "replayed",
	}); !errors.Is(err, ErrRefreshTokenReplayed) {
		t.Fatalf("RotateRefreshToken() replay error = %v, want ErrRefreshTokenReplayed", err)
	}

	got, err := client.Get(ctx, "rotation-test")
	if err != nil {
		t.Fatal(err)
	}
	if got.TokenRotation != current.TokenRotation+1 {
		t.Errorf("TokenRotation = %d, want %d", got.TokenRotation, current.TokenRotation+1)
	}
	if got.RefreshToken != "next" {
		t.Errorf("RefreshToken = %q, want %q", got.RefreshToken, "next")
	}
	if got.APIToken != "api-token" {
		t.Errorf("APIToken = %q, want preserved %q", got.APIToken, "api-token")
	}
	if got.CompletedAt == nil {
		t.Error("CompletedAt should be preserved (set on the earlier UpdateStatus)")
	}
}

func TestClient_RotateRefreshTokenRejectsInactiveSession(t *testing.T) {
	client := testClient(t)
	ctx := context.Background()

	if _, err := client.Create(ctx, "inactive-rotation-test", "verifier", ""); err != nil {
		t.Fatal(err)
	}

	err := client.RotateRefreshToken(ctx, "inactive-rotation-test", 0, Status{
		Phase: PhaseActive, RefreshToken: "next",
	})
	if err == nil || errors.Is(err, ErrRefreshTokenReplayed) {
		t.Fatalf("RotateRefreshToken() on a Pending session error = %v, want a plain 'not active' error", err)
	}
}

func TestClient_RotateRefreshTokenRejectsScrubbedToken(t *testing.T) {
	client := testClient(t)
	ctx := context.Background()

	if _, err := client.Create(ctx, "empty-token-test", "verifier", ""); err != nil {
		t.Fatal(err)
	}
	if err := client.UpdateStatus(ctx, "empty-token-test", Status{Phase: PhaseActive, RefreshToken: ""}); err != nil {
		t.Fatal(err)
	}

	err := client.RotateRefreshToken(ctx, "empty-token-test", 0, Status{Phase: PhaseActive, RefreshToken: "next"})
	if !errors.Is(err, ErrRefreshTokenReplayed) {
		t.Errorf("RotateRefreshToken() on a session without a stored token error = %v, want ErrRefreshTokenReplayed", err)
	}
}

func TestClient_Revoke(t *testing.T) {
	client := testClient(t)
	ctx := context.Background()

	if _, err := client.Create(ctx, "revoke-test", "verifier", "user@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := client.UpdateStatus(ctx, "revoke-test", Status{
		Phase: PhaseActive, RefreshToken: "refresh-secret", APIToken: "api-secret",
	}); err != nil {
		t.Fatal(err)
	}

	if err := client.Revoke(ctx, "revoke-test"); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}

	got, err := client.Get(ctx, "revoke-test")
	if err != nil {
		t.Fatal(err)
	}
	if got.Phase != PhaseRevoked {
		t.Errorf("Phase = %q, want %q", got.Phase, PhaseRevoked)
	}
	if got.RevokedAt == nil {
		t.Error("RevokedAt should be set after revocation")
	}
	if got.RefreshToken != "" || got.APIToken != "" {
		t.Error("credentials should be scrubbed after revocation")
	}

	if err := client.Revoke(ctx, "revoke-test"); err != nil {
		t.Errorf("Revoke() on an already-revoked session should be a no-op, got error = %v", err)
	}
}

func TestClient_Revoke_NotFound(t *testing.T) {
	client := testClient(t)
	ctx := context.Background()
	if err := client.Revoke(ctx, "does-not-exist"); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("Revoke() error = %v, want wrapped ErrSessionNotFound", err)
	}
}

func TestClient_ListActiveExcludesTerminal(t *testing.T) {
	client := testClient(t)
	ctx := context.Background()

	if _, err := client.Create(ctx, "list-active-1", "v", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Create(ctx, "list-active-2", "v", ""); err != nil {
		t.Fatal(err)
	}
	if err := client.Revoke(ctx, "list-active-2"); err != nil {
		t.Fatal(err)
	}

	active, err := client.ListActive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 1 || active[0].SessionID != "list-active-1" {
		t.Errorf("ListActive() = %+v, want only list-active-1", active)
	}

	all, err := client.ListAll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Errorf("ListAll() len = %d, want 2", len(all))
	}
}

func TestClient_GetByUser(t *testing.T) {
	client := testClient(t)
	ctx := context.Background()

	if _, err := client.Create(ctx, "byuser-pending", "v", "user@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Create(ctx, "byuser-active", "v", ""); err != nil {
		t.Fatal(err)
	}
	if err := client.UpdateStatus(ctx, "byuser-active", Status{Phase: PhaseActive, Email: "user@example.com"}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Create(ctx, "byuser-other", "v", "other@example.com"); err != nil {
		t.Fatal(err)
	}

	got, err := client.GetByUser(ctx, "user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("GetByUser() len = %d, want 2, got %+v", len(got), got)
	}
}

func TestClient_ValidateSession(t *testing.T) {
	client := testClient(t)
	ctx := context.Background()

	if _, err := client.Create(ctx, "validate-test", "v", "user@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := client.UpdateStatus(ctx, "validate-test", Status{Phase: PhaseActive}); err != nil {
		t.Fatal(err)
	}

	if err := client.ValidateSession(ctx, "validate-test", PhaseActive); err != nil {
		t.Errorf("ValidateSession() correct phase error = %v", err)
	}
	if err := client.ValidateSession(ctx, "validate-test", PhaseRevoked); err == nil {
		t.Error("ValidateSession() wrong phase should error")
	}
	if err := client.ValidateSession(ctx, "nonexistent", PhaseActive); err == nil {
		t.Error("ValidateSession() nonexistent session should error")
	}
}

func TestClient_UpdateLastUsed(t *testing.T) {
	client := testClient(t)
	ctx := context.Background()

	if _, err := client.Create(ctx, "lastused-test", "v", "user@example.com"); err != nil {
		t.Fatal(err)
	}
	before, _ := client.Get(ctx, "lastused-test")
	if !before.LastUsed.IsZero() {
		t.Error("LastUsed should be zero initially")
	}
	if err := client.UpdateLastUsed(ctx, "lastused-test"); err != nil {
		t.Fatal(err)
	}
	after, _ := client.Get(ctx, "lastused-test")
	if after.LastUsed.IsZero() {
		t.Error("LastUsed should be set after update")
	}
}

func TestClient_TouchLastUsed(t *testing.T) {
	client := testClient(t)
	ctx := context.Background()

	if _, err := client.Create(ctx, "touch-test", "v", "user@example.com"); err != nil {
		t.Fatal(err)
	}

	const window = time.Minute
	if err := client.TouchLastUsed(ctx, "touch-test", window); err != nil {
		t.Fatalf("first touch error = %v", err)
	}
	first, _ := client.Get(ctx, "touch-test")
	if first.LastUsed.IsZero() {
		t.Fatal("LastUsed should be set after first touch")
	}

	if err := client.TouchLastUsed(ctx, "touch-test", window); err != nil {
		t.Fatalf("second touch error = %v", err)
	}
	second, _ := client.Get(ctx, "touch-test")
	if !second.LastUsed.Equal(first.LastUsed) {
		t.Errorf("LastUsed changed within throttle window: first=%v second=%v", first.LastUsed, second.LastUsed)
	}

	if err := client.TouchLastUsed(ctx, "touch-test", 0); err != nil {
		t.Fatalf("forced touch error = %v", err)
	}
	third, _ := client.Get(ctx, "touch-test")
	if third.LastUsed.Before(first.LastUsed) {
		t.Errorf("LastUsed regressed: first=%v third=%v", first.LastUsed, third.LastUsed)
	}

	if err := client.TouchLastUsed(ctx, "nonexistent-touch", window); err != nil {
		t.Errorf("TouchLastUsed() on a nonexistent session should be a silent no-op, got error = %v", err)
	}
}

func TestClient_UpdateUserID(t *testing.T) {
	client := testClient(t)
	ctx := context.Background()

	if _, err := client.Create(ctx, "userid-test", "v", ""); err != nil {
		t.Fatal(err)
	}
	if err := client.UpdateUserID(ctx, "userid-test", "newuser@example.com"); err != nil {
		t.Fatal(err)
	}
	got, _ := client.Get(ctx, "userid-test")
	if got.UserID != "newuser@example.com" {
		t.Errorf("UserID = %q, want %q", got.UserID, "newuser@example.com")
	}
	if got.LastUsed.IsZero() {
		t.Error("LastUsed should be set when updating UserID")
	}
}

func TestClient_Delete(t *testing.T) {
	client := testClient(t)
	ctx := context.Background()

	if _, err := client.Create(ctx, "delete-test", "v", "user@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := client.Delete(ctx, "delete-test"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Get(ctx, "delete-test"); !errors.Is(err, ErrSessionNotFound) {
		t.Error("Get() should fail after Delete()")
	}
}

func TestClient_Delete_Nonexistent(t *testing.T) {
	client := testClient(t)
	ctx := context.Background()
	if err := client.Delete(ctx, "nonexistent"); err == nil {
		t.Error("Delete() should fail for nonexistent session")
	}
}

func TestClient_CleanupOldSessions(t *testing.T) {
	client := testClient(t)
	ctx := context.Background()

	if _, err := client.Create(ctx, "cleanup-fresh-pending", "v", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Create(ctx, "cleanup-stale-pending", "v", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := client.pool.Exec(ctx, `UPDATE oauth_sessions SET created_at = now() - interval '1 hour' WHERE session_id=$1`, "cleanup-stale-pending"); err != nil {
		t.Fatal(err)
	}

	if _, err := client.Create(ctx, "cleanup-old-revoked", "v", ""); err != nil {
		t.Fatal(err)
	}
	if err := client.Revoke(ctx, "cleanup-old-revoked"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.pool.Exec(ctx, `UPDATE oauth_sessions SET revoked_at = now() - interval '48 hours' WHERE session_id=$1`, "cleanup-old-revoked"); err != nil {
		t.Fatal(err)
	}

	if _, err := client.Create(ctx, "cleanup-active", "v", "user@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := client.UpdateStatus(ctx, "cleanup-active", Status{Phase: PhaseActive}); err != nil {
		t.Fatal(err)
	}

	if err := client.CleanupOldSessions(ctx, 24*time.Hour, 5*time.Minute); err != nil {
		t.Fatal(err)
	}

	remaining, err := client.ListAll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ids := make(map[string]bool)
	for _, s := range remaining {
		ids[s.SessionID] = true
	}
	if !ids["cleanup-fresh-pending"] {
		t.Error("fresh pending session should survive cleanup")
	}
	if !ids["cleanup-active"] {
		t.Error("active session should survive cleanup")
	}
	if ids["cleanup-stale-pending"] {
		t.Error("stale pending session should have been deleted")
	}
	if ids["cleanup-old-revoked"] {
		t.Error("old revoked session should have been deleted")
	}
}

func TestClient_ExpireInactiveSessions(t *testing.T) {
	client := testClient(t)
	ctx := context.Background()

	if _, err := client.Create(ctx, "expire-active-stale", "v", "user@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := client.UpdateStatus(ctx, "expire-active-stale", Status{
		Phase: PhaseActive, RefreshToken: "secret", APIToken: "secret",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.pool.Exec(ctx, `UPDATE oauth_sessions SET created_at = now() - interval '2 hours' WHERE session_id=$1`, "expire-active-stale"); err != nil {
		t.Fatal(err)
	}

	if _, err := client.Create(ctx, "expire-active-fresh", "v", "user@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := client.UpdateStatus(ctx, "expire-active-fresh", Status{Phase: PhaseActive}); err != nil {
		t.Fatal(err)
	}

	if err := client.ExpireInactiveSessions(ctx, time.Hour); err != nil {
		t.Fatal(err)
	}

	stale, err := client.Get(ctx, "expire-active-stale")
	if err != nil {
		t.Fatal(err)
	}
	if stale.Phase != PhaseExpired {
		t.Errorf("stale session Phase = %q, want %q", stale.Phase, PhaseExpired)
	}
	if stale.ExpiredAt == nil {
		t.Error("ExpiredAt should be set")
	}
	if stale.RefreshToken != "" || stale.APIToken != "" {
		t.Error("credentials should be scrubbed on expiry")
	}

	fresh, err := client.Get(ctx, "expire-active-fresh")
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Phase != PhaseActive {
		t.Errorf("fresh session Phase = %q, want unchanged %q", fresh.Phase, PhaseActive)
	}
}
