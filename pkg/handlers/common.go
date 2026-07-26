package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"kauth/pkg/oauth"

	"github.com/coreos/go-oidc/v3/oidc"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
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

// decodeJSON decodes a bounded request body as JSON into v.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
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
	caData, err := base64.StdEncoding.DecodeString(kg.ClusterCA)
	if err != nil {
		slog.Error("failed to decode cluster CA", "error", err)
		return ""
	}
	config := clientcmdapi.NewConfig()
	config.Clusters[kg.ClusterName] = &clientcmdapi.Cluster{
		Server:                   kg.ClusterServer,
		CertificateAuthorityData: caData,
	}
	config.AuthInfos[email] = &clientcmdapi.AuthInfo{Exec: &clientcmdapi.ExecConfig{
		APIVersion:      "client.authentication.k8s.io/v1",
		Command:         "kauth",
		Args:            []string{"get-token"},
		InteractiveMode: clientcmdapi.NeverExecInteractiveMode,
	}}
	config.Contexts[contextName] = &clientcmdapi.Context{
		Cluster:   kg.ClusterName,
		AuthInfo:  email,
		Namespace: "default",
	}
	config.CurrentContext = contextName
	data, err := clientcmd.Write(*config)
	if err != nil {
		slog.Error("failed to generate kubeconfig", "error", err)
		return ""
	}
	return string(data)
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
