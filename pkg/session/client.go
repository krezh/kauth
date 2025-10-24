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
func (c *Client) Create(ctx context.Context, state, verifier string) (*v1alpha1.OAuthSession, error) {
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
			CreatedAt: metav1.Now(),
		},
		Status: v1alpha1.OAuthSessionStatus{
			Ready: false,
		},
	}

	unstructuredObj := &unstructured.Unstructured{}
	unstructuredMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(session)
	if err != nil {
		return nil, fmt.Errorf("failed to convert to unstructured: %w", err)
	}
	unstructuredObj.Object = unstructuredMap

	result, err := c.dynamicClient.Resource(c.gvr()).Namespace(c.namespace).Create(
		ctx,
		unstructuredObj,
		metav1.CreateOptions{},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create OAuthSession: %w", err)
	}

	var created v1alpha1.OAuthSession
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(result.Object, &created); err != nil {
		return nil, fmt.Errorf("failed to convert from unstructured: %w", err)
	}

	return &created, nil
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
	// Get current session
	session, err := c.Get(ctx, state)
	if err != nil {
		return fmt.Errorf("failed to get session: %w", err)
	}

	// Update status
	session.Status = status
	if status.Ready {
		now := metav1.Now()
		session.Status.CompletedAt = &now
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

		if session.Spec.CreatedAt.Time.Before(cutoff) {
			_ = c.Delete(ctx, session.Spec.State)
		}
	}

	return nil
}

// sanitizeName converts OAuth state to valid Kubernetes resource name
// Kubernetes names must be lowercase alphanumeric characters, '-' or '.',
// and must start and end with an alphanumeric character (RFC 1123 subdomain)
func sanitizeName(state string) string {
	// Use a prefix to avoid collision with other resources
	sanitized := validation.SanitizeToResourceName(state)
	// Ensure we don't exceed 63 chars with the prefix
	if len(sanitized)+6 > 63 {
		sanitized = sanitized[:57]
	}
	return "oauth-" + sanitized
}
