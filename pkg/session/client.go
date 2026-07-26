package session

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
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
	"k8s.io/client-go/util/retry"
)

var ErrPreconditionFailed = errors.New("session precondition failed")

const (
	refreshLockAnnotation       = "kauth.io/refresh-lock"
	refreshLockExpiryAnnotation = "kauth.io/refresh-lock-expiry"
	refreshResultAnnotation     = "kauth.io/refresh-result"
	sessionExpiryAnnotation     = "kauth.io/session-expires-at"
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

// NewClientForDynamic creates an OAuthSession client from an existing dynamic client.
func NewClientForDynamic(dynamicClient dynamic.Interface, namespace string) *Client {
	return &Client{
		dynamicClient: dynamicClient,
		namespace:     namespace,
	}
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
func (c *Client) Create(ctx context.Context, sessionID, verifier, userID string) (*v1alpha1.OAuthSession, error) {
	session := &v1alpha1.OAuthSession{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "kauth.io/v1alpha1",
			Kind:       "OAuthSession",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      sanitizeName(sessionID),
			Namespace: c.namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "kauth",
			},
		},
		Spec: v1alpha1.OAuthSessionSpec{
			SessionID: sessionID,
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
	if err := c.UpdateStatus(ctx, sessionID, v1alpha1.OAuthSessionStatus{
		Phase: v1alpha1.SessionPending,
	}); err != nil {
		_ = c.Delete(ctx, sessionID)
		return nil, fmt.Errorf("failed to set initial session status: %w", err)
	}

	return c.Get(ctx, sessionID)
}

// Get retrieves an OAuthSession by session ID
func (c *Client) Get(ctx context.Context, sessionID string) (*v1alpha1.OAuthSession, error) {
	result, err := c.dynamicClient.Resource(c.gvr()).Namespace(c.namespace).Get(
		ctx,
		sanitizeName(sessionID),
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

// GetRefreshResult returns the encrypted previous result and current session state.
func (c *Client) GetRefreshResult(ctx context.Context, sessionID string, ttl time.Duration) (*v1alpha1.OAuthSession, string, error) {
	session, err := c.Get(ctx, sessionID)
	if err != nil {
		return nil, "", err
	}
	result := session.Annotations[refreshResultAnnotation]
	if session.Status.Phase != v1alpha1.SessionActive || sessionExpired(session, ttl) || result == "" {
		return nil, "", ErrPreconditionFailed
	}
	return session, result, nil
}

// ConsumePendingVerifier atomically claims a pending OAuth callback.
func (c *Client) ConsumePendingVerifier(ctx context.Context, sessionID string, ttl time.Duration) (string, error) {
	var verifier string
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		session, err := c.Get(ctx, sessionID)
		if err != nil {
			return err
		}
		if session.Status.Phase != v1alpha1.SessionPending || session.Spec.Verifier == "" ||
			session.Spec.CreatedAt.IsZero() || !time.Now().Before(session.Spec.CreatedAt.Add(ttl)) {
			return ErrPreconditionFailed
		}

		verifier = session.Spec.Verifier
		session.Spec.Verifier = ""
		unstructuredMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(session)
		if err != nil {
			return fmt.Errorf("failed to convert to unstructured: %w", err)
		}
		_, err = c.dynamicClient.Resource(c.gvr()).Namespace(c.namespace).Update(
			ctx,
			&unstructured.Unstructured{Object: unstructuredMap},
			metav1.UpdateOptions{},
		)
		return err
	})
	if err != nil {
		return "", fmt.Errorf("failed to consume session verifier: %w", err)
	}
	return verifier, nil
}

// ClaimRefreshToken serializes upstream refresh operations across server pods.
func (c *Client) ClaimRefreshToken(ctx context.Context, sessionID, expectedRefreshToken string, lockTTL, sessionTTL time.Duration) (string, error) {
	lockID := rand.Text()
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		session, err := c.Get(ctx, sessionID)
		if err != nil {
			return err
		}
		if session.Status.Phase != v1alpha1.SessionActive || session.Status.RefreshToken != expectedRefreshToken {
			return ErrPreconditionFailed
		}
		if sessionExpired(session, sessionTTL) {
			return ErrPreconditionFailed
		}
		if session.Annotations == nil {
			session.Annotations = make(map[string]string)
		}
		if current := session.Annotations[refreshLockAnnotation]; current != "" {
			expiresAt, parseErr := time.Parse(time.RFC3339Nano, session.Annotations[refreshLockExpiryAnnotation])
			if parseErr == nil && time.Now().Before(expiresAt) {
				return ErrPreconditionFailed
			}
		}
		session.Annotations[refreshLockAnnotation] = lockID
		session.Annotations[refreshLockExpiryAnnotation] = time.Now().Add(lockTTL).Format(time.RFC3339Nano)

		unstructuredMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(session)
		if err != nil {
			return fmt.Errorf("failed to convert to unstructured: %w", err)
		}
		_, err = c.dynamicClient.Resource(c.gvr()).Namespace(c.namespace).Update(
			ctx,
			&unstructured.Unstructured{Object: unstructuredMap},
			metav1.UpdateOptions{},
		)
		return err
	})
	if err != nil {
		return "", fmt.Errorf("failed to claim refresh token: %w", err)
	}
	return lockID, nil
}

// ExtendRefreshTokenClaim records successful refresh activity while the caller
// still owns the upstream-refresh claim.
func (c *Client) ExtendRefreshTokenClaim(ctx context.Context, sessionID, lockID string, ttl time.Duration) error {
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		session, err := c.Get(ctx, sessionID)
		if err != nil {
			return err
		}
		if session.Status.Phase != v1alpha1.SessionActive || session.Annotations[refreshLockAnnotation] != lockID || sessionExpired(session, ttl) {
			return ErrPreconditionFailed
		}
		now := metav1.Now()
		session.Spec.LastUsed = now
		setSessionExpiry(session, now.Add(ttl))

		unstructuredMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(session)
		if err != nil {
			return fmt.Errorf("failed to convert to unstructured: %w", err)
		}
		_, err = c.dynamicClient.Resource(c.gvr()).Namespace(c.namespace).Update(
			ctx,
			&unstructured.Unstructured{Object: unstructuredMap},
			metav1.UpdateOptions{},
		)
		return err
	})
	if err != nil {
		return fmt.Errorf("failed to extend refresh claim: %w", err)
	}
	return nil
}

// StageRefreshResult persists an encrypted retry result before committing rotation.
func (c *Client) StageRefreshResult(ctx context.Context, sessionID, lockID, encryptedResult string) error {
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		session, err := c.Get(ctx, sessionID)
		if err != nil {
			return err
		}
		if session.Status.Phase != v1alpha1.SessionActive || session.Annotations[refreshLockAnnotation] != lockID {
			return ErrPreconditionFailed
		}
		if session.Annotations == nil {
			session.Annotations = make(map[string]string)
		}
		session.Annotations[refreshResultAnnotation] = encryptedResult

		unstructuredMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(session)
		if err != nil {
			return fmt.Errorf("failed to convert to unstructured: %w", err)
		}
		_, err = c.dynamicClient.Resource(c.gvr()).Namespace(c.namespace).Update(
			ctx,
			&unstructured.Unstructured{Object: unstructuredMap},
			metav1.UpdateOptions{},
		)
		return err
	})
	if err != nil {
		return fmt.Errorf("failed to stage refresh result: %w", err)
	}
	return nil
}

// ReleaseRefreshTokenClaim releases a claim if it is still owned by lockID.
func (c *Client) ReleaseRefreshTokenClaim(ctx context.Context, sessionID, lockID string) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		session, err := c.Get(ctx, sessionID)
		if err != nil {
			return err
		}
		if session.Annotations[refreshLockAnnotation] != lockID {
			return nil
		}
		delete(session.Annotations, refreshLockAnnotation)
		delete(session.Annotations, refreshLockExpiryAnnotation)

		unstructuredMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(session)
		if err != nil {
			return fmt.Errorf("failed to convert to unstructured: %w", err)
		}
		_, err = c.dynamicClient.Resource(c.gvr()).Namespace(c.namespace).Update(
			ctx,
			&unstructured.Unstructured{Object: unstructuredMap},
			metav1.UpdateOptions{},
		)
		return err
	})
}

// RotateRefreshToken replaces the stored refresh token only if the presented
// token and upstream-refresh claim are still current.
func (c *Client) RotateRefreshToken(ctx context.Context, sessionID, expectedRefreshToken, lockID string, status v1alpha1.OAuthSessionStatus) error {
	if status.Phase != v1alpha1.SessionActive {
		return ErrPreconditionFailed
	}

	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		session, err := c.Get(ctx, sessionID)
		if err != nil {
			return err
		}
		if session.Status.Phase != v1alpha1.SessionActive || session.Status.RefreshToken != expectedRefreshToken ||
			session.Annotations[refreshLockAnnotation] != lockID {
			return ErrPreconditionFailed
		}
		if sessionExpired(session, 0) {
			return ErrPreconditionFailed
		}

		existingWebhookToken := session.Status.WebhookToken
		existingCompletedAt := session.Status.CompletedAt
		session.Status = status
		if session.Status.WebhookToken == "" {
			session.Status.WebhookToken = existingWebhookToken
		}
		if session.Status.CompletedAt == nil {
			session.Status.CompletedAt = existingCompletedAt
		}

		unstructuredMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(session)
		if err != nil {
			return fmt.Errorf("failed to convert to unstructured: %w", err)
		}
		_, err = c.dynamicClient.Resource(c.gvr()).Namespace(c.namespace).UpdateStatus(
			ctx,
			&unstructured.Unstructured{Object: unstructuredMap},
			metav1.UpdateOptions{},
		)
		return err
	})
	if err != nil {
		return fmt.Errorf("failed to rotate refresh token: %w", err)
	}
	return nil
}

// UpdateStatus updates the status of an OAuthSession
func (c *Client) UpdateStatus(ctx context.Context, sessionID string, status v1alpha1.OAuthSessionStatus) error {
	session, err := c.Get(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("failed to get session: %w", err)
	}

	// Refuse to re-activate a session that has reached a terminal state.
	// This closes the TOCTOU window where a concurrent revoke between
	// ValidateSession and UpdateStatus would be silently undone.
	if status.Phase == v1alpha1.SessionActive &&
		(session.Status.Phase == v1alpha1.SessionRevoked || session.Status.Phase == v1alpha1.SessionExpired) {
		return fmt.Errorf("session is in terminal state %s, cannot reactivate", session.Status.Phase)
	}

	existingWebhookToken := session.Status.WebhookToken
	existingCompletedAt := session.Status.CompletedAt
	session.Status = status
	// Preserve the WebhookToken across status updates that don't explicitly set one.
	// The token is created once at login and must survive subsequent refresh cycles.
	if status.WebhookToken == "" && existingWebhookToken != "" {
		session.Status.WebhookToken = existingWebhookToken
	}
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
func (c *Client) Revoke(ctx context.Context, sessionID string) error {
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		session, err := c.Get(ctx, sessionID)
		if err != nil {
			return err
		}
		if session.Status.Phase == v1alpha1.SessionRevoked {
			return nil
		}

		now := metav1.Now()
		session.Status.Phase = v1alpha1.SessionRevoked
		session.Status.RevokedAt = &now
		unstructuredMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(session)
		if err != nil {
			return fmt.Errorf("failed to convert to unstructured: %w", err)
		}
		_, err = c.dynamicClient.Resource(c.gvr()).Namespace(c.namespace).UpdateStatus(
			ctx,
			&unstructured.Unstructured{Object: unstructuredMap},
			metav1.UpdateOptions{},
		)
		return err
	})
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
func (c *Client) ValidateSession(ctx context.Context, sessionID string, expectedPhase v1alpha1.SessionPhase) error {
	session, err := c.Get(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("session not found: %w", err)
	}

	if session.Status.Phase != expectedPhase {
		return fmt.Errorf("session is %s, expected %s", session.Status.Phase, expectedPhase)
	}

	return nil
}

// UpdateLastUsed updates the last used timestamp for a session
func (c *Client) UpdateLastUsed(ctx context.Context, sessionID string) error {
	session, err := c.Get(ctx, sessionID)
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

// TouchActiveSession updates LastUsed only while the session remains active and
// returns the identity from the same resource version used for the update.
func (c *Client) TouchActiveSession(ctx context.Context, sessionID, expectedWebhookToken string, ttl time.Duration) (*v1alpha1.OAuthSession, error) {
	var touched *v1alpha1.OAuthSession
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		session, err := c.Get(ctx, sessionID)
		if err != nil {
			return err
		}
		if session.Status.Phase != v1alpha1.SessionActive || sessionExpired(session, ttl) ||
			subtle.ConstantTimeCompare([]byte(session.Status.WebhookToken), []byte(expectedWebhookToken)) != 1 {
			return ErrPreconditionFailed
		}
		now := metav1.Now()
		session.Spec.LastUsed = now
		setSessionExpiry(session, now.Add(ttl))

		unstructuredMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(session)
		if err != nil {
			return fmt.Errorf("failed to convert to unstructured: %w", err)
		}
		result, err := c.dynamicClient.Resource(c.gvr()).Namespace(c.namespace).Update(
			ctx,
			&unstructured.Unstructured{Object: unstructuredMap},
			metav1.UpdateOptions{},
		)
		if err != nil {
			return err
		}
		var updated v1alpha1.OAuthSession
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(result.Object, &updated); err != nil {
			return fmt.Errorf("failed to convert from unstructured: %w", err)
		}
		touched = &updated
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to touch active session: %w", err)
	}
	return touched, nil
}

func sessionExpired(session *v1alpha1.OAuthSession, ttl time.Duration) bool {
	if rawExpiry, found := session.Annotations[sessionExpiryAnnotation]; found {
		expiresAt, err := time.Parse(time.RFC3339Nano, rawExpiry)
		return err != nil || !time.Now().Before(expiresAt)
	}
	if !session.Spec.ExpiresAt.IsZero() {
		return !time.Now().Before(session.Spec.ExpiresAt.Time)
	}
	lastActivity := session.Spec.CreatedAt.Time
	if !session.Spec.LastUsed.IsZero() {
		lastActivity = session.Spec.LastUsed.Time
	}
	return lastActivity.IsZero() || !time.Now().Before(lastActivity.Add(ttl))
}

func setSessionExpiry(session *v1alpha1.OAuthSession, expiresAt time.Time) {
	if session.Annotations == nil {
		session.Annotations = make(map[string]string)
	}
	session.Annotations[sessionExpiryAnnotation] = expiresAt.UTC().Format(time.RFC3339Nano)
	session.Spec.ExpiresAt = metav1.NewTime(expiresAt)
}

// UpdateUserID updates the user ID in the session spec
func (c *Client) UpdateUserID(ctx context.Context, sessionID, userID string, ttl time.Duration) error {
	session, err := c.Get(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("failed to get session: %w", err)
	}

	session.Spec.UserID = userID
	now := metav1.Now()
	session.Spec.LastUsed = now
	setSessionExpiry(session, now.Add(ttl))

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

		// Match on Status.Email (set after OAuth callback) or Spec.UserID
		// (set earlier via UpdateUserID) so that in-progress sessions are
		// included in bulk revoke operations.
		if session.Status.Email == userID || session.Spec.UserID == userID {
			userSessions = append(userSessions, session)
		}
	}

	return userSessions, nil
}

// Delete deletes an OAuthSession
func (c *Client) Delete(ctx context.Context, sessionID string) error {
	err := c.dynamicClient.Resource(c.gvr()).Namespace(c.namespace).Delete(
		ctx,
		sanitizeName(sessionID),
		metav1.DeleteOptions{},
	)
	if err != nil {
		return fmt.Errorf("failed to delete OAuthSession: %w", err)
	}
	return nil
}

// Watch watches for OAuthSession changes, resuming from resourceVersion if non-empty.
func (c *Client) Watch(ctx context.Context, resourceVersion string) (watch.Interface, error) {
	return c.dynamicClient.Resource(c.gvr()).Namespace(c.namespace).Watch(
		ctx,
		metav1.ListOptions{
			LabelSelector:       "app.kubernetes.io/managed-by=kauth",
			ResourceVersion:     resourceVersion,
			AllowWatchBookmarks: true,
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
			_ = c.Delete(ctx, session.Spec.SessionID)
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

	for _, item := range list.Items {
		var session v1alpha1.OAuthSession
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(item.Object, &session); err != nil {
			continue
		}

		// Only expire active sessions
		if session.Status.Phase != v1alpha1.SessionActive {
			continue
		}

		expired := sessionExpired(&session, ttl)

		if expired {
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

// sanitizeName converts a session ID to a valid Kubernetes resource name
func sanitizeName(sessionID string) string {
	sanitized := validation.SanitizeToResourceName(sessionID)
	if len(sanitized)+6 > 63 {
		sanitized = strings.TrimRight(sanitized[:57], "-.")
	}
	return "oauth-" + sanitized
}
