package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// OAuthSession represents a temporary OAuth authentication session
type OAuthSession struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitzero"`

	Spec   OAuthSessionSpec   `json:"spec"`
	Status OAuthSessionStatus `json:"status,omitzero"`
}

// OAuthSessionSpec defines the desired state of an OAuth session
type OAuthSessionSpec struct {
	// State is the OAuth state parameter for CSRF protection
	State string `json:"state"`

	// Verifier is the PKCE verifier for code exchange
	Verifier string `json:"verifier"`

	// CreatedAt is when the session was created
	CreatedAt metav1.Time `json:"createdAt"`
}

// OAuthSessionStatus defines the observed state of an OAuth session
type OAuthSessionStatus struct {
	// Ready indicates whether the OAuth flow has completed successfully
	Ready bool `json:"ready"`

	// Email is the authenticated user's email address
	Email string `json:"email,omitempty"`

	// RefreshToken is the JWT refresh token for token rotation
	RefreshToken string `json:"refreshToken,omitempty"`

	// Error contains any error message if the OAuth flow failed
	Error string `json:"error,omitempty"`

	// CompletedAt is when the OAuth flow completed
	CompletedAt *metav1.Time `json:"completedAt,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// OAuthSessionList contains a list of OAuthSession
type OAuthSessionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []OAuthSession `json:"items"`
}
