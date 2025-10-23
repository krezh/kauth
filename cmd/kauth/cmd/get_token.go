package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

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

// ExecCredential is the Kubernetes exec credential format
type ExecCredential struct {
	APIVersion string                `json:"apiVersion"`
	Kind       string                `json:"kind"`
	Status     *ExecCredentialStatus `json:"status,omitempty"`
}

type ExecCredentialStatus struct {
	Token               string     `json:"token"`
	ExpirationTimestamp *time.Time `json:"expirationTimestamp,omitempty"`
}

// TokenCache represents cached token info
type TokenCache struct {
	IDToken           string    `json:"id_token"`
	KauthRefreshToken string    `json:"kauth_refresh_token"`
	ExpiresAt         time.Time `json:"expires_at"`
}

// RefreshRequest is sent to the server to refresh tokens
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// RefreshResponse is returned by the server after token refresh
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
	tokenCachePath := filepath.Join(cacheDir, "kauth-token-cache.json")
	refreshTokenPath := filepath.Join(cacheDir, "kauth-refresh-token")
	serverURLPath := filepath.Join(cacheDir, "kauth-server-url")

	// Read server URL from cache
	serverURLBytes, err := os.ReadFile(serverURLPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("no authentication found. Please run 'kauth login --url <server-url>' first")
		}
		return fmt.Errorf("failed to read server URL: %w", err)
	}
	serverURL := string(serverURLBytes)

	// Try to load cached token
	cachedToken, err := loadTokenCache(tokenCachePath)
	if err == nil && cachedToken != nil {
		// Check if token is still valid (with 5 minute buffer)
		if time.Now().Before(cachedToken.ExpiresAt.Add(-5 * time.Minute)) {
			// Token is still valid, return it
			return outputExecCredential(cachedToken.IDToken, cachedToken.ExpiresAt)
		}
	}

	// Token expired or not found, try to refresh
	refreshToken, err := os.ReadFile(refreshTokenPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("no authentication found. Please run 'kauth login --url <server-url>' first")
		}
		return fmt.Errorf("failed to read refresh token: %w", err)
	}

	if len(refreshToken) == 0 {
		return fmt.Errorf("refresh token is empty. Please run 'kauth login --url <server-url>' first")
	}

	// Refresh the token
	refreshResp, err := refreshTokenFromServer(serverURL, string(refreshToken))
	if err != nil {
		return fmt.Errorf("failed to refresh token: %w. Please run 'kauth login --url <server-url>' again", err)
	}

	// Save new refresh token
	if refreshResp.RefreshToken != "" {
		if err := os.WriteFile(refreshTokenPath, []byte(refreshResp.RefreshToken), 0600); err != nil {
			// Non-fatal, just log to stderr
			fmt.Fprintf(os.Stderr, "Warning: failed to save new refresh token: %v\n", err)
		}
	}

	// Cache the new token
	expiresAt := time.Now().Add(time.Duration(refreshResp.ExpiresIn) * time.Second)
	newCache := TokenCache{
		IDToken:           refreshResp.IDToken,
		KauthRefreshToken: refreshResp.RefreshToken,
		ExpiresAt:         expiresAt,
	}
	if err := saveTokenCache(tokenCachePath, &newCache); err != nil {
		// Non-fatal
		fmt.Fprintf(os.Stderr, "Warning: failed to cache token: %v\n", err)
	}

	// Output the token in exec credential format
	return outputExecCredential(refreshResp.IDToken, expiresAt)
}

func loadTokenCache(path string) (*TokenCache, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cache TokenCache
	if err := json.Unmarshal(data, &cache); err != nil {
		return nil, err
	}

	return &cache, nil
}

func saveTokenCache(path string, cache *TokenCache) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
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
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	var refreshResp RefreshResponse
	if err := json.NewDecoder(resp.Body).Decode(&refreshResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &refreshResp, nil
}

func outputExecCredential(token string, expiresAt time.Time) error {
	execCred := ExecCredential{
		APIVersion: "client.authentication.k8s.io/v1",
		Kind:       "ExecCredential",
		Status: &ExecCredentialStatus{
			Token:               token,
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
