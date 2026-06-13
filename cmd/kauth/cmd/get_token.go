package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"kauth/pkg/token"

	"github.com/spf13/cobra"
)

var httpClient = &http.Client{
	Timeout: 30 * time.Second,
}

var getTokenCmd = &cobra.Command{
	Use:   "get-token",
	Short: "Get current authentication token (for kubectl exec plugin)",
	Long: `Get the current authentication token, automatically refreshing if needed.

This command is designed to be used as a Kubernetes exec credential plugin
in kubeconfig. It will automatically refresh expired tokens using the stored
refresh token. The server URL is automatically read from the login cache.`,
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

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type RefreshResponse struct {
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	TokenType    string `json:"token_type"`
	Kubeconfig   string `json:"kubeconfig"`
}

func runGetToken(cmd *cobra.Command, args []string) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	cacheDir := filepath.Join(homeDir, ".kube", "cache")
	serverURLPath := filepath.Join(cacheDir, "kauth-server-url")

	storage := token.NewStorage(token.DefaultCachePath())

	serverURLBytes, err := os.ReadFile(serverURLPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("not authenticated.\n\nTo authenticate, run:\n  kauth login --url <server-url>\n\nExample:\n  kauth login --url https://kauth.example.com")
		}
		return fmt.Errorf("failed to read server URL: %w", err)
	}
	serverURL := string(serverURLBytes)

	cachedToken, err := storage.Load()
	if err == nil && cachedToken != nil {
		if time.Now().Before(cachedToken.Expiry.Add(-5 * time.Minute)) {
			return outputExecCredential(cachedToken.IDToken, cachedToken.Expiry)
		}
	}

	if cachedToken == nil || cachedToken.RefreshToken == "" {
		return fmt.Errorf("no refresh token found.\n\nYour authentication session may have expired.\nTo re-authenticate, run:\n  kauth login")
	}

	refreshResp, err := refreshTokenFromServer(serverURL, cachedToken.RefreshToken)
	if err != nil {
		return fmt.Errorf("failed to refresh token: %w\n\nYour refresh token may have expired.\nTo re-authenticate, run:\n  kauth login", err)
	}

	expiresAt := time.Now().Add(time.Duration(refreshResp.ExpiresIn) * time.Second)
	newCache := &token.Cache{
		IDToken:      refreshResp.IDToken,
		RefreshToken: refreshResp.RefreshToken,
		SessionID:    cachedToken.SessionID,
		Expiry:       expiresAt,
	}

	if err := storage.Save(newCache); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to cache token: %v\n", err)
	}

	return outputExecCredential(refreshResp.IDToken, expiresAt)
}

func refreshTokenFromServer(baseURL, refreshToken string) (*RefreshResponse, error) {
	reqBody := RefreshRequest{
		RefreshToken: refreshToken,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := httpClient.Post(
		baseURL+"/refresh",
		"application/json",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to server: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	var refreshResp RefreshResponse
	if err := json.NewDecoder(resp.Body).Decode(&refreshResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &refreshResp, nil
}

func outputExecCredential(tok string, expiresAt time.Time) error {
	execCred := ExecCredential{
		APIVersion: "client.authentication.k8s.io/v1",
		Kind:       "ExecCredential",
		Status: &ExecCredentialStatus{
			Token:               tok,
			ExpirationTimestamp: &expiresAt,
		},
	}

	data, err := json.MarshalIndent(execCred, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal exec credential: %w", err)
	}

	fmt.Println(string(data))
	return nil
}
