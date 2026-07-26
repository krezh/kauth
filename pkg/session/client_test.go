package session

import (
	"context"
	"errors"
	"testing"
	"time"

	v1alpha1 "kauth/pkg/apis/kauth.io/v1alpha1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

func newFakeClient(t *testing.T) *Client {
	t.Helper()

	scheme := runtime.NewScheme()
	gvr := schema.GroupVersionResource{
		Group:    "kauth.io",
		Version:  "v1alpha1",
		Resource: "oauthsessions",
	}
	gvk := schema.GroupVersionKind{
		Group:   "kauth.io",
		Version: "v1alpha1",
		Kind:    "OAuthSession",
	}
	gvkList := schema.GroupVersionKind{
		Group:   "kauth.io",
		Version: "v1alpha1",
		Kind:    "OAuthSessionList",
	}
	scheme.AddKnownTypeWithName(gvk, &v1alpha1.OAuthSession{})
	scheme.AddKnownTypeWithName(gvkList, &v1alpha1.OAuthSessionList{})
	metav1.AddToGroupVersion(scheme, schema.GroupVersion{Group: "kauth.io", Version: "v1alpha1"})

	fakeClient := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme,
		map[schema.GroupVersionResource]string{
			gvr: "OAuthSessionList",
		},
	)

	return &Client{
		dynamicClient: fakeClient,
		namespace:     "default",
	}
}

func TestClient_Create(t *testing.T) {
	client := newFakeClient(t)
	ctx := context.Background()

	session, err := client.Create(ctx, "test-state-123", "test-verifier", "user@example.com")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if session.Spec.SessionID != "test-state-123" {
		t.Errorf("SessionID = %q, want %q", session.Spec.SessionID, "test-state-123")
	}
	if session.Spec.Verifier != "test-verifier" {
		t.Errorf("Verifier = %q, want %q", session.Spec.Verifier, "test-verifier")
	}
	if session.Spec.UserID != "user@example.com" {
		t.Errorf("UserID = %q, want %q", session.Spec.UserID, "user@example.com")
	}
	if session.Status.Phase != v1alpha1.SessionPending {
		t.Errorf("Phase = %q, want %q", session.Status.Phase, v1alpha1.SessionPending)
	}
	if session.Spec.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set")
	}
}

func TestClient_Create_EmptyUserID(t *testing.T) {
	client := newFakeClient(t)
	ctx := context.Background()

	session, err := client.Create(ctx, "no-user-id", "verifier", "")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if session.Spec.UserID != "" {
		t.Errorf("UserID = %q, want empty", session.Spec.UserID)
	}
}

func TestClient_Get(t *testing.T) {
	client := newFakeClient(t)
	ctx := context.Background()

	created, err := client.Create(ctx, "test-state-456", "verifier", "user@example.com")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	got, err := client.Get(ctx, "test-state-456")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	if got.Spec.SessionID != created.Spec.SessionID {
		t.Errorf("SessionID = %q, want %q", got.Spec.SessionID, created.Spec.SessionID)
	}
	if got.Spec.UserID != created.Spec.UserID {
		t.Errorf("UserID = %q, want %q", got.Spec.UserID, created.Spec.UserID)
	}
	if got.Spec.Verifier != created.Spec.Verifier {
		t.Errorf("Verifier = %q, want %q", got.Spec.Verifier, created.Spec.Verifier)
	}
}

func TestClient_Get_NotFound(t *testing.T) {
	client := newFakeClient(t)
	ctx := context.Background()

	_, err := client.Get(ctx, "nonexistent-state")
	if err == nil {
		t.Error("Get() expected error for nonexistent session, got nil")
	}
}

func TestClient_ConsumePendingVerifier(t *testing.T) {
	client := newFakeClient(t)
	ctx := context.Background()
	_, err := client.Create(ctx, "consume-test", "verifier", "")
	if err != nil {
		t.Fatal(err)
	}

	verifier, err := client.ConsumePendingVerifier(ctx, "consume-test", time.Minute)
	if err != nil {
		t.Fatalf("ConsumePendingVerifier() error = %v", err)
	}
	if verifier != "verifier" {
		t.Errorf("verifier = %q, want verifier", verifier)
	}
	if _, err := client.ConsumePendingVerifier(ctx, "consume-test", time.Minute); !errors.Is(err, ErrPreconditionFailed) {
		t.Errorf("second ConsumePendingVerifier() error = %v, want ErrPreconditionFailed", err)
	}
}

func TestClient_RotateRefreshToken(t *testing.T) {
	client := newFakeClient(t)
	ctx := context.Background()
	_, err := client.Create(ctx, "rotate-test", "verifier", "user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	completed := metav1.Now()
	err = client.UpdateStatus(ctx, "rotate-test", v1alpha1.OAuthSessionStatus{
		Phase:        v1alpha1.SessionActive,
		Email:        "user@example.com",
		RefreshToken: "old-token",
		WebhookToken: "webhook-token",
		CompletedAt:  &completed,
	})
	if err != nil {
		t.Fatal(err)
	}

	lockID, err := client.ClaimRefreshToken(ctx, "rotate-test", "old-token", time.Minute, time.Hour)
	if err != nil {
		t.Fatalf("ClaimRefreshToken() error = %v", err)
	}
	if _, err := client.ClaimRefreshToken(ctx, "rotate-test", "old-token", time.Minute, time.Hour); !errors.Is(err, ErrPreconditionFailed) {
		t.Errorf("concurrent ClaimRefreshToken() error = %v, want ErrPreconditionFailed", err)
	}
	if err := client.ExtendRefreshTokenClaim(ctx, "rotate-test", lockID, time.Hour); err != nil {
		t.Fatalf("ExtendRefreshTokenClaim() error = %v", err)
	}
	err = client.RotateRefreshToken(ctx, "rotate-test", "old-token", lockID, v1alpha1.OAuthSessionStatus{
		Phase:        v1alpha1.SessionActive,
		Email:        "user@example.com",
		RefreshToken: "new-token",
	})
	if err != nil {
		t.Fatalf("RotateRefreshToken() error = %v", err)
	}
	got, err := client.Get(ctx, "rotate-test")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status.RefreshToken != "new-token" || got.Status.WebhookToken != "webhook-token" || got.Status.CompletedAt == nil {
		t.Errorf("RotateRefreshToken() stored unexpected status: %+v", got.Status)
	}
	if err := client.RotateRefreshToken(ctx, "rotate-test", "old-token", lockID, v1alpha1.OAuthSessionStatus{Phase: v1alpha1.SessionActive}); !errors.Is(err, ErrPreconditionFailed) {
		t.Errorf("stale RotateRefreshToken() error = %v, want ErrPreconditionFailed", err)
	}
	if err := client.ReleaseRefreshTokenClaim(ctx, "rotate-test", lockID); err != nil {
		t.Errorf("ReleaseRefreshTokenClaim() error = %v", err)
	}
}

func TestClient_UpdateStatus(t *testing.T) {
	client := newFakeClient(t)
	ctx := context.Background()

	_, err := client.Create(ctx, "test-state-789", "verifier", "user@example.com")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	newStatus := v1alpha1.OAuthSessionStatus{
		Phase:        v1alpha1.SessionActive,
		Email:        "user@example.com",
		Username:     "testuser",
		RefreshToken: "encrypted-refresh-token",
	}

	err = client.UpdateStatus(ctx, "test-state-789", newStatus)
	if err != nil {
		t.Fatalf("UpdateStatus() error = %v", err)
	}

	got, err := client.Get(ctx, "test-state-789")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	if got.Status.Phase != v1alpha1.SessionActive {
		t.Errorf("Phase = %q, want %q", got.Status.Phase, v1alpha1.SessionActive)
	}
	if got.Status.Email != "user@example.com" {
		t.Errorf("Email = %q, want %q", got.Status.Email, "user@example.com")
	}
	if got.Status.Username != "testuser" {
		t.Errorf("Username = %q, want %q", got.Status.Username, "testuser")
	}
	if got.Status.RefreshToken != "encrypted-refresh-token" {
		t.Errorf("RefreshToken = %q, want %q", got.Status.RefreshToken, "encrypted-refresh-token")
	}
	if got.Status.CompletedAt == nil {
		t.Error("CompletedAt should be set when phase is Active")
	}
}

func TestClient_UpdateStatus_PendingNoCompletedAt(t *testing.T) {
	client := newFakeClient(t)
	ctx := context.Background()

	_, _ = client.Create(ctx, "pending-test", "verifier", "user@example.com")

	err := client.UpdateStatus(ctx, "pending-test", v1alpha1.OAuthSessionStatus{
		Phase: v1alpha1.SessionPending,
		Error: "some error",
	})
	if err != nil {
		t.Fatalf("UpdateStatus() error = %v", err)
	}

	got, _ := client.Get(ctx, "pending-test")
	if got.Status.CompletedAt != nil {
		t.Error("CompletedAt should NOT be set when phase is Pending")
	}
}

func TestClient_Revoke(t *testing.T) {
	client := newFakeClient(t)
	ctx := context.Background()

	_, err := client.Create(ctx, "revoke-test", "verifier", "user@example.com")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	err = client.Revoke(ctx, "revoke-test")
	if err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}

	got, err := client.Get(ctx, "revoke-test")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	if got.Status.Phase != v1alpha1.SessionRevoked {
		t.Errorf("Phase = %q, want %q", got.Status.Phase, v1alpha1.SessionRevoked)
	}
	if got.Status.RevokedAt == nil {
		t.Error("RevokedAt should be set after revocation")
	}
}

func TestClient_ValidateSession(t *testing.T) {
	client := newFakeClient(t)
	ctx := context.Background()

	_, _ = client.Create(ctx, "validate-test", "verifier", "user@example.com")
	_ = client.UpdateStatus(ctx, "validate-test", v1alpha1.OAuthSessionStatus{Phase: v1alpha1.SessionActive})

	t.Run("validates correct phase", func(t *testing.T) {
		err := client.ValidateSession(ctx, "validate-test", v1alpha1.SessionActive)
		if err != nil {
			t.Errorf("ValidateSession() error = %v", err)
		}
	})

	t.Run("fails on wrong phase", func(t *testing.T) {
		err := client.ValidateSession(ctx, "validate-test", v1alpha1.SessionRevoked)
		if err == nil {
			t.Error("ValidateSession() expected error for wrong phase, got nil")
		}
	})

	t.Run("fails on nonexistent session", func(t *testing.T) {
		err := client.ValidateSession(ctx, "nonexistent", v1alpha1.SessionActive)
		if err == nil {
			t.Error("ValidateSession() expected error for nonexistent session, got nil")
		}
	})
}

func TestClient_UpdateLastUsed(t *testing.T) {
	client := newFakeClient(t)
	ctx := context.Background()

	_, err := client.Create(ctx, "lastused-test", "verifier", "user@example.com")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	before, _ := client.Get(ctx, "lastused-test")
	if !before.Spec.LastUsed.IsZero() {
		t.Error("LastUsed should be zero initially")
	}

	err = client.UpdateLastUsed(ctx, "lastused-test")
	if err != nil {
		t.Fatalf("UpdateLastUsed() error = %v", err)
	}

	after, _ := client.Get(ctx, "lastused-test")
	if after.Spec.LastUsed.IsZero() {
		t.Error("LastUsed should be set after update")
	}
}

func TestClient_TouchActiveSession(t *testing.T) {
	client := newFakeClient(t)
	ctx := context.Background()
	_, err := client.Create(ctx, "touch-test", "verifier", "user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := client.UpdateStatus(ctx, "touch-test", v1alpha1.OAuthSessionStatus{
		Phase:        v1alpha1.SessionActive,
		Email:        "user@example.com",
		WebhookToken: "webhook-token",
	}); err != nil {
		t.Fatal(err)
	}

	touched, err := client.TouchActiveSession(ctx, "touch-test", "webhook-token", time.Hour)
	if err != nil {
		t.Fatalf("TouchActiveSession() error = %v", err)
	}
	if touched.Spec.LastUsed.IsZero() {
		t.Error("TouchActiveSession() did not update LastUsed")
	}
	if touched.Spec.ExpiresAt.IsZero() || !touched.Spec.ExpiresAt.After(touched.Spec.LastUsed.Time) {
		t.Error("TouchActiveSession() did not extend ExpiresAt")
	}
	if err := client.Revoke(ctx, "touch-test"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.TouchActiveSession(ctx, "touch-test", "webhook-token", time.Hour); !errors.Is(err, ErrPreconditionFailed) {
		t.Errorf("TouchActiveSession() on revoked session error = %v, want ErrPreconditionFailed", err)
	}
}

func TestClient_TouchActiveSessionRejectsExpiredAndReplacedToken(t *testing.T) {
	client := newFakeClient(t)
	ctx := context.Background()
	_, err := client.Create(ctx, "expired-touch", "verifier", "user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := client.UpdateUserID(ctx, "expired-touch", "user@example.com", -time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := client.UpdateStatus(ctx, "expired-touch", v1alpha1.OAuthSessionStatus{
		Phase:        v1alpha1.SessionActive,
		WebhookToken: "current-token",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.TouchActiveSession(ctx, "expired-touch", "current-token", time.Hour); !errors.Is(err, ErrPreconditionFailed) {
		t.Errorf("expired TouchActiveSession() error = %v, want ErrPreconditionFailed", err)
	}

	_, err = client.Create(ctx, "replaced-token", "verifier", "user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := client.UpdateUserID(ctx, "replaced-token", "user@example.com", time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := client.UpdateStatus(ctx, "replaced-token", v1alpha1.OAuthSessionStatus{
		Phase:        v1alpha1.SessionActive,
		WebhookToken: "current-token",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.TouchActiveSession(ctx, "replaced-token", "old-token", time.Hour); !errors.Is(err, ErrPreconditionFailed) {
		t.Errorf("replaced-token TouchActiveSession() error = %v, want ErrPreconditionFailed", err)
	}
}

func TestClient_UpdateUserID(t *testing.T) {
	client := newFakeClient(t)
	ctx := context.Background()

	_, err := client.Create(ctx, "userid-test", "verifier", "")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	err = client.UpdateUserID(ctx, "userid-test", "newuser@example.com", time.Hour)
	if err != nil {
		t.Fatalf("UpdateUserID() error = %v", err)
	}

	got, _ := client.Get(ctx, "userid-test")
	if got.Spec.UserID != "newuser@example.com" {
		t.Errorf("UserID = %q, want %q", got.Spec.UserID, "newuser@example.com")
	}
	if got.Spec.LastUsed.IsZero() {
		t.Error("LastUsed should be set when updating UserID")
	}
}

func TestClient_Delete(t *testing.T) {
	client := newFakeClient(t)
	ctx := context.Background()

	_, err := client.Create(ctx, "delete-test", "verifier", "user@example.com")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	err = client.Delete(ctx, "delete-test")
	if err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	_, err = client.Get(ctx, "delete-test")
	if err == nil {
		t.Error("Get() should fail after Delete()")
	}
}

func TestClient_Delete_Nonexistent(t *testing.T) {
	client := newFakeClient(t)
	ctx := context.Background()

	err := client.Delete(ctx, "nonexistent")
	if err == nil {
		t.Error("Delete() should fail for nonexistent session")
	}
}
