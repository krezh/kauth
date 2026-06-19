package cmd

import (
	"encoding/json"
	"fmt"
	"time"

	"kauth/pkg/token"

	"github.com/spf13/cobra"
)

var getTokenCmd = &cobra.Command{
	Use:   "get-token",
	Short: "Get current authentication token (for kubectl exec plugin)",
	Long: `Get the current authentication token for use as a Kubernetes exec credential plugin.

The token is a long-lived encrypted session credential. kubectl caches it until
the session expires. Revocation takes effect within the API server's webhook
cache TTL (default 30s). Re-run kauth login after expiry or revocation.`,
	RunE: runGetToken,
}

func init() {
	rootCmd.AddCommand(getTokenCmd)
}

type ExecCredential struct {
	APIVersion string                `json:"apiVersion"`
	Kind       string                `json:"kind"`
	Status     *ExecCredentialStatus `json:"status,omitempty"`
}

type ExecCredentialStatus struct {
	Token               string     `json:"token"`
	ExpirationTimestamp *time.Time `json:"expirationTimestamp,omitempty"`
}

func runGetToken(cmd *cobra.Command, args []string) error {
	storage := token.NewStorage(token.DefaultCachePath())

	cachedToken, err := storage.Load()
	if err != nil || cachedToken == nil || cachedToken.ServerURL == "" {
		return fmt.Errorf("not authenticated.\n\nTo authenticate, run:\n  kauth login --url <server-url>\n\nExample:\n  kauth login --url https://kauth.example.com")
	}

	if cachedToken.WebhookToken != "" {
		if cachedToken.Expiry.IsZero() || time.Now().Before(cachedToken.Expiry.Add(-5*time.Minute)) {
			return outputExecCredential(cachedToken.WebhookToken, cachedToken.Expiry)
		}
		return fmt.Errorf("session expired.\n\nTo re-authenticate, run:\n  kauth login")
	}

	return fmt.Errorf("no webhook token found.\n\nYour authentication session may be from an older version of kauth.\nTo re-authenticate, run:\n  kauth login")
}

func outputExecCredential(tok string, expiresAt time.Time) error {
	execCred := ExecCredential{
		APIVersion: "client.authentication.k8s.io/v1",
		Kind:       "ExecCredential",
		Status: &ExecCredentialStatus{
			Token: tok,
		},
	}
	if !expiresAt.IsZero() {
		execCred.Status.ExpirationTimestamp = &expiresAt
	}

	data, err := json.MarshalIndent(execCred, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal exec credential: %w", err)
	}

	fmt.Println(string(data))
	return nil
}
