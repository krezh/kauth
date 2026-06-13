package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SessionPhase represents the lifecycle phase of a session
type SessionPhase string

const (
	SessionPending  SessionPhase = "Pending"
	SessionActive   SessionPhase = "Active"
	SessionRevoked  SessionPhase = "Revoked"
	SessionExpired  SessionPhase = "Expired"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// OAuthSession represents an OAuth authentication session
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

	// UserID is the user identifier (email or sub)
	UserID string `json:"userID,omitempty"`

	// CreatedAt is when the session was created
	CreatedAt metav1.Time `json:"createdAt"`

	// LastUsed is when the session was last used for token refresh
	LastUsed metav1.Time `json:"lastUsed,omitempty"`
}

// OAuthSessionStatus defines the observed state of an OAuth session
type OAuthSessionStatus struct {
	// Phase indicates the lifecycle phase of the session
	Phase SessionPhase `json:"phase,omitempty"`

	// Email is the authenticated user's email address
	Email string `json:"email,omitempty"`

	// Username is the authenticated user's preferred username
	Username string `json:"username,omitempty"`

	// RefreshToken is the encrypted JWT refresh token for token rotation
	RefreshToken string `json:"refreshToken,omitempty"`

	// RevokedAt is when the session was revoked
	RevokedAt *metav1.Time `json:"revokedAt,omitempty"`

	// CompletedAt is when the OAuth flow completed
	CompletedAt *metav1.Time `json:"completedAt,omitempty"`

	// Error contains any error message if the OAuth flow failed
	Error string `json:"error,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// OAuthSessionList contains a list of OAuthSession
type OAuthSessionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []OAuthSession `json:"items"`
}
