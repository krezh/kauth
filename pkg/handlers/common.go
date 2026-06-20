package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"kauth/pkg/oauth"

	"github.com/coreos/go-oidc/v3/oidc"
)

// OIDCClaims represents the common claims structure from OIDC tokens
type OIDCClaims struct {
	Email             string   `json:"email"`
	Groups            []string `json:"groups"`
	Name              string   `json:"name"`
	Sub               string   `json:"sub"`
	PreferredUsername string   `json:"preferred_username"`
}

// KubeconfigGenerator generates kubeconfig YAML
type KubeconfigGenerator struct {
	ClusterName   string
	ClusterServer string
	ClusterCA     string
}

// writeJSON writes v as JSON with Content-Type set. Encoding errors are logged but not returned.
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("failed to encode JSON response", "error", err)
	}
}

// decodeJSON decodes the request body as JSON into v.
func decodeJSON(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}

// Generate creates a kubeconfig for the given user
func (kg *KubeconfigGenerator) Generate(email, username string) string {
	if username == "" {
		if local, _, ok := strings.Cut(email, "@"); ok {
			username = local
		} else {
			username = email
		}
	}
	contextName := fmt.Sprintf("%s@%s", username, kg.ClusterName)
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
    namespace: default
current-context: %s
`, kg.ClusterName, kg.ClusterServer, kg.ClusterCA,
		email,
		contextName, kg.ClusterName, email,
		contextName)
}

// VerifyAndExtractClaims verifies an ID token and extracts claims
func VerifyAndExtractClaims(ctx context.Context, provider *oauth.Provider, idToken string) (*OIDCClaims, *oidc.IDToken, error) {
	verified, err := provider.VerifyIDToken(ctx, idToken)
	if err != nil {
		return nil, nil, fmt.Errorf("ID token verification failed: %w", err)
	}

	var claims OIDCClaims
	if err := verified.Claims(&claims); err != nil {
		slog.WarnContext(ctx, "failed to extract claims from ID token", "error", err)
		return nil, nil, fmt.Errorf("failed to extract claims: %w", err)
	}

	return &claims, verified, nil
}
