package credential

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"golang.org/x/oauth2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauthv1 "k8s.io/client-go/pkg/apis/clientauthentication/v1"
)

// ExecCredential represents the kubectl exec credential plugin format
type ExecCredential struct {
	TypeMeta metav1.TypeMeta                    `json:",inline"`
	Status   *clientauthv1.ExecCredentialStatus `json:"status,omitzero"`
}

// OutputCredential outputs an oauth2.Token in the kubectl exec credential format
func OutputCredential(token *oauth2.Token) error {
	if token == nil {
		return fmt.Errorf("token is nil")
	}

	// Extract ID token (this is what Kubernetes validates, not the access token)
	idToken, ok := token.Extra("id_token").(string)
	if !ok || idToken == "" {
		return fmt.Errorf("no id_token found in token - ensure your OIDC provider includes ID tokens")
	}

	// Build ExecCredential structure
	cred := &clientauthv1.ExecCredential{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "client.authentication.k8s.io/v1",
			Kind:       "ExecCredential",
		},
		Status: &clientauthv1.ExecCredentialStatus{
			Token: idToken,
		},
	}

	// Include expiration timestamp if available
	if !token.Expiry.IsZero() {
		expiry := metav1.NewTime(token.Expiry)
		cred.Status.ExpirationTimestamp = &expiry
	}

	// Marshal to JSON and write to stdout
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(cred); err != nil {
		return fmt.Errorf("failed to encode credential: %w", err)
	}

	return nil
}

// IsTokenValid checks if a token is still valid
func IsTokenValid(token *oauth2.Token) bool {
	if token == nil {
		return false
	}

	// Check if token has an ID token
	if _, ok := token.Extra("id_token").(string); !ok {
		return false
	}

	// Check if token is expired (with 1 minute buffer)
	return token.Valid() && time.Until(token.Expiry) > time.Minute
}
