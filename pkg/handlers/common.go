package handlers

import (
	"context"
	"fmt"
	"log"

	"kauth/pkg/metrics"
	"kauth/pkg/oauth"

	"github.com/coreos/go-oidc/v3/oidc"
)

// OIDCClaims represents the common claims structure from OIDC tokens
type OIDCClaims struct {
	Email  string   `json:"email"`
	Groups []string `json:"groups"`
	Name   string   `json:"name"`
	Sub    string   `json:"sub"`
}

// KubeconfigGenerator generates kubeconfig YAML
type KubeconfigGenerator struct {
	ClusterName   string
	ClusterServer string
	ClusterCA     string
}

// Generate creates a kubeconfig for the given user email
func (kg *KubeconfigGenerator) Generate(email string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: %s
  cluster:
    server: %s
    certificate-authority-data: %s
users:
- name: %s
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: kauth
      args:
      - get-token
      interactiveMode: Never
contexts:
- name: %s
  context:
    cluster: %s
    user: %s
current-context: %s
`, kg.ClusterName, kg.ClusterServer, kg.ClusterCA,
		email,
		kg.ClusterName, kg.ClusterName, email,
		kg.ClusterName)
}

// VerifyAndExtractClaims verifies an ID token and extracts claims
func VerifyAndExtractClaims(ctx context.Context, provider *oauth.Provider, idToken string) (*OIDCClaims, *oidc.IDToken, error) {
	verified, err := provider.VerifyIDToken(ctx, idToken)
	if err != nil {
		metrics.RecordOIDCRequest("verify_id_token", "failure")
		return nil, nil, fmt.Errorf("ID token verification failed: %w", err)
	}
	metrics.RecordOIDCRequest("verify_id_token", "success")

	var claims OIDCClaims
	if err := verified.Claims(&claims); err != nil {
		log.Printf("Failed to extract claims from ID token: %v", err)
		return nil, nil, fmt.Errorf("failed to extract claims: %w", err)
	}

	return &claims, verified, nil
}
