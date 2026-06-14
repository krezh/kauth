package session

import (
	"context"
	"testing"

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

func TestClient_UpdateUserID(t *testing.T) {
	client := newFakeClient(t)
	ctx := context.Background()

	_, err := client.Create(ctx, "userid-test", "verifier", "")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	err = client.UpdateUserID(ctx, "userid-test", "newuser@example.com")
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
