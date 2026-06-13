package session

import (
	"context"
	"fmt"
	"time"

	v1alpha1 "kauth/pkg/apis/kauth.io/v1alpha1"
	"kauth/pkg/validation"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

// Client wraps Kubernetes dynamic client for OAuthSession operations
type Client struct {
	dynamicClient dynamic.Interface
	namespace     string
}

// NewClient creates a new OAuthSession client
func NewClient(config *rest.Config, namespace string) (*Client, error) {
	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create dynamic client: %w", err)
	}

	return &Client{
		dynamicClient: dynamicClient,
		namespace:     namespace,
	}, nil
}

// gvr returns the GroupVersionResource for OAuthSession
func (c *Client) gvr() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    "kauth.io",
		Version:  "v1alpha1",
		Resource: "oauthsessions",
	}
}

// Create creates a new OAuthSession
func (c *Client) Create(ctx context.Context, state, verifier, userID string) (*v1alpha1.OAuthSession, error) {
	session := &v1alpha1.OAuthSession{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "kauth.io/v1alpha1",
			Kind:       "OAuthSession",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      sanitizeName(state),
			Namespace: c.namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "kauth",
			},
		},
		Spec: v1alpha1.OAuthSessionSpec{
			State:     state,
			Verifier:  verifier,
			UserID:    userID,
			CreatedAt: metav1.Now(),
		},
		Status: v1alpha1.OAuthSessionStatus{
			Phase: v1alpha1.SessionPending,
		},
	}

	unstructuredObj := &unstructured.Unstructured{}
	unstructuredMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(session)
	if err != nil {
		return nil, fmt.Errorf("failed to convert to unstructured: %w", err)
	}
	unstructuredObj.Object = unstructuredMap

	_, err = c.dynamicClient.Resource(c.gvr()).Namespace(c.namespace).Create(
		ctx,
		unstructuredObj,
		metav1.CreateOptions{},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create OAuthSession: %w", err)
	}

	// The CRD has a status subresource, so the API server strips the status field
	// from Create. Set Phase=Pending explicitly via UpdateStatus.
	if err := c.UpdateStatus(ctx, state, v1alpha1.OAuthSessionStatus{
		Phase: v1alpha1.SessionPending,
	}); err != nil {
		_ = c.Delete(ctx, state)
		return nil, fmt.Errorf("failed to set initial session status: %w", err)
	}

	return c.Get(ctx, state)
}

// Get retrieves an OAuthSession by state
func (c *Client) Get(ctx context.Context, state string) (*v1alpha1.OAuthSession, error) {
	result, err := c.dynamicClient.Resource(c.gvr()).Namespace(c.namespace).Get(
		ctx,
		sanitizeName(state),
		metav1.GetOptions{},
	)
	if err != nil {
		return nil, err
	}

	var session v1alpha1.OAuthSession
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(result.Object, &session); err != nil {
		return nil, fmt.Errorf("failed to convert from unstructured: %w", err)
	}

	return &session, nil
}

// UpdateStatus updates the status of an OAuthSession
func (c *Client) UpdateStatus(ctx context.Context, state string, status v1alpha1.OAuthSessionStatus) error {
	session, err := c.Get(ctx, state)
	if err != nil {
		return fmt.Errorf("failed to get session: %w", err)
	}

	existingCompletedAt := session.Status.CompletedAt
	session.Status = status
	if status.Phase == v1alpha1.SessionActive && status.CompletedAt == nil {
		if existingCompletedAt != nil {
			session.Status.CompletedAt = existingCompletedAt
		} else {
			now := metav1.Now()
			session.Status.CompletedAt = &now
		}
	}

	unstructuredObj := &unstructured.Unstructured{}
	unstructuredMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(session)
	if err != nil {
		return fmt.Errorf("failed to convert to unstructured: %w", err)
	}
	unstructuredObj.Object = unstructuredMap

	_, err = c.dynamicClient.Resource(c.gvr()).Namespace(c.namespace).UpdateStatus(
		ctx,
		unstructuredObj,
		metav1.UpdateOptions{},
	)
	if err != nil {
		return fmt.Errorf("failed to update status: %w", err)
	}

	return nil
}

// Revoke marks a session as revoked
func (c *Client) Revoke(ctx context.Context, state string) error {
	session, err := c.Get(ctx, state)
	if err != nil {
		return fmt.Errorf("failed to get session: %w", err)
	}

	if session.Status.Phase == v1alpha1.SessionRevoked {
		return nil
	}

	now := metav1.Now()
	session.Status.Phase = v1alpha1.SessionRevoked
	session.Status.RevokedAt = &now

	unstructuredObj := &unstructured.Unstructured{}
	unstructuredMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(session)
	if err != nil {
		return fmt.Errorf("failed to convert to unstructured: %w", err)
	}
	unstructuredObj.Object = unstructuredMap

	_, err = c.dynamicClient.Resource(c.gvr()).Namespace(c.namespace).UpdateStatus(
		ctx,
		unstructuredObj,
		metav1.UpdateOptions{},
	)
	if err != nil {
		return fmt.Errorf("failed to revoke session: %w", err)
	}

	return nil
}

// ListActive returns all sessions that are not revoked or expired
func (c *Client) ListActive(ctx context.Context) ([]v1alpha1.OAuthSession, error) {
	list, err := c.dynamicClient.Resource(c.gvr()).Namespace(c.namespace).List(
		ctx,
		metav1.ListOptions{
			LabelSelector: "app.kubernetes.io/managed-by=kauth",
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list sessions: %w", err)
	}

	var active []v1alpha1.OAuthSession
	for _, item := range list.Items {
		var session v1alpha1.OAuthSession
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(item.Object, &session); err != nil {
			continue
		}

		if session.Status.Phase != v1alpha1.SessionRevoked && session.Status.Phase != v1alpha1.SessionExpired {
			active = append(active, session)
		}
	}

	return active, nil
}

// ValidateSession checks if a session exists and has the expected phase
func (c *Client) ValidateSession(ctx context.Context, state string, expectedPhase v1alpha1.SessionPhase) error {
	session, err := c.Get(ctx, state)
	if err != nil {
		return fmt.Errorf("session not found: %w", err)
	}

	if session.Status.Phase != expectedPhase {
		return fmt.Errorf("session is %s, expected %s", session.Status.Phase, expectedPhase)
	}

	return nil
}

// UpdateLastUsed updates the last used timestamp for a session
func (c *Client) UpdateLastUsed(ctx context.Context, state string) error {
	session, err := c.Get(ctx, state)
	if err != nil {
		return fmt.Errorf("failed to get session: %w", err)
	}

	session.Spec.LastUsed = metav1.Now()

	unstructuredObj := &unstructured.Unstructured{}
	unstructuredMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(session)
	if err != nil {
		return fmt.Errorf("failed to convert to unstructured: %w", err)
	}
	unstructuredObj.Object = unstructuredMap

	_, err = c.dynamicClient.Resource(c.gvr()).Namespace(c.namespace).Update(
		ctx,
		unstructuredObj,
		metav1.UpdateOptions{},
	)
	if err != nil {
		return fmt.Errorf("failed to update last used: %w", err)
	}

	return nil
}

// UpdateUserID updates the user ID in the session spec
func (c *Client) UpdateUserID(ctx context.Context, state, userID string) error {
	session, err := c.Get(ctx, state)
	if err != nil {
		return fmt.Errorf("failed to get session: %w", err)
	}

	session.Spec.UserID = userID
	session.Spec.LastUsed = metav1.Now()

	unstructuredObj := &unstructured.Unstructured{}
	unstructuredMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(session)
	if err != nil {
		return fmt.Errorf("failed to convert to unstructured: %w", err)
	}
	unstructuredObj.Object = unstructuredMap

	_, err = c.dynamicClient.Resource(c.gvr()).Namespace(c.namespace).Update(
		ctx,
		unstructuredObj,
		metav1.UpdateOptions{},
	)
	if err != nil {
		return fmt.Errorf("failed to update user ID: %w", err)
	}

	return nil
}

// GetByUser returns all sessions for a specific user
func (c *Client) GetByUser(ctx context.Context, userID string) ([]v1alpha1.OAuthSession, error) {
	list, err := c.dynamicClient.Resource(c.gvr()).Namespace(c.namespace).List(
		ctx,
		metav1.ListOptions{
			LabelSelector: "app.kubernetes.io/managed-by=kauth",
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list sessions: %w", err)
	}

	var userSessions []v1alpha1.OAuthSession
	for _, item := range list.Items {
		var session v1alpha1.OAuthSession
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(item.Object, &session); err != nil {
			continue
		}

		if session.Spec.UserID == userID {
			userSessions = append(userSessions, session)
		}
	}

	return userSessions, nil
}

// Delete deletes an OAuthSession
func (c *Client) Delete(ctx context.Context, state string) error {
	err := c.dynamicClient.Resource(c.gvr()).Namespace(c.namespace).Delete(
		ctx,
		sanitizeName(state),
		metav1.DeleteOptions{},
	)
	if err != nil {
		return fmt.Errorf("failed to delete OAuthSession: %w", err)
	}
	return nil
}

// Watch watches for OAuthSession changes
func (c *Client) Watch(ctx context.Context) (watch.Interface, error) {
	return c.dynamicClient.Resource(c.gvr()).Namespace(c.namespace).Watch(
		ctx,
		metav1.ListOptions{
			LabelSelector: "app.kubernetes.io/managed-by=kauth",
		},
	)
}

// CleanupOldSessions deletes sessions older than the specified TTL
// Only deletes sessions that are Revoked or Expired
func (c *Client) CleanupOldSessions(ctx context.Context, ttl time.Duration) error {
	list, err := c.dynamicClient.Resource(c.gvr()).Namespace(c.namespace).List(
		ctx,
		metav1.ListOptions{
			LabelSelector: "app.kubernetes.io/managed-by=kauth",
		},
	)
	if err != nil {
		return fmt.Errorf("failed to list sessions: %w", err)
	}

	cutoff := time.Now().Add(-ttl)

	for _, item := range list.Items {
		var session v1alpha1.OAuthSession
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(item.Object, &session); err != nil {
			continue
		}

		// Only delete terminal or stale pending sessions; skip active ones
		phase := session.Status.Phase
		if phase != v1alpha1.SessionRevoked && phase != v1alpha1.SessionExpired && phase != v1alpha1.SessionPending {
			continue
		}

		// For revoked sessions use RevokedAt so freshly-revoked CRDs are kept
		// long enough for all pods to observe the revocation before deletion.
		var ageRef time.Time
		if phase == v1alpha1.SessionRevoked && session.Status.RevokedAt != nil {
			ageRef = session.Status.RevokedAt.Time
		} else {
			ageRef = session.Spec.CreatedAt.Time
		}

		if ageRef.Before(cutoff) {
			_ = c.Delete(ctx, session.Spec.State)
		}
	}

	return nil
}

// ExpireInactiveSessions marks sessions as expired if they haven't been used within the TTL
func (c *Client) ExpireInactiveSessions(ctx context.Context, ttl time.Duration) error {
	list, err := c.dynamicClient.Resource(c.gvr()).Namespace(c.namespace).List(
		ctx,
		metav1.ListOptions{
			LabelSelector: "app.kubernetes.io/managed-by=kauth",
		},
	)
	if err != nil {
		return fmt.Errorf("failed to list sessions: %w", err)
	}

	cutoff := time.Now().Add(-ttl)

	for _, item := range list.Items {
		var session v1alpha1.OAuthSession
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(item.Object, &session); err != nil {
			continue
		}

		// Only expire active sessions
		if session.Status.Phase != v1alpha1.SessionActive {
			continue
		}

		// Use LastUsed if set, otherwise use CreatedAt
		lastActivity := session.Spec.CreatedAt.Time
		if !session.Spec.LastUsed.IsZero() {
			lastActivity = session.Spec.LastUsed.Time
		}

		if lastActivity.Before(cutoff) {
			session.Status.Phase = v1alpha1.SessionExpired
			unstructuredObj := &unstructured.Unstructured{}
			unstructuredMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&session)
			if err != nil {
				continue
			}
			unstructuredObj.Object = unstructuredMap

			_, _ = c.dynamicClient.Resource(c.gvr()).Namespace(c.namespace).UpdateStatus(
				ctx,
				unstructuredObj,
				metav1.UpdateOptions{},
			)
		}
	}

	return nil
}

// sanitizeName converts OAuth state to valid Kubernetes resource name
func sanitizeName(state string) string {
	sanitized := validation.SanitizeToResourceName(state)
	if len(sanitized)+6 > 63 {
		sanitized = sanitized[:57]
	}
	return "oauth-" + sanitized
}
