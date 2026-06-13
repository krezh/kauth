package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"kauth/pkg/token"

	"github.com/spf13/cobra"
)

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Revoke current session and clear local cache",
	Long:  `Revoke the current authentication session on the server and clear the local token cache.`,
	RunE:  runLogout,
}

func init() {
	rootCmd.AddCommand(logoutCmd)
}

type RevokeRequest struct {
	SessionID string `json:"session_id,omitempty"`
}

func runLogout(cmd *cobra.Command, args []string) error {
	storage := token.NewStorage(token.DefaultCachePath())

	cachedToken, err := storage.Load()
	if err != nil || cachedToken == nil || cachedToken.RefreshToken == "" {
		fmt.Println("Not authenticated.")
		return nil
	}

	serverURL := cachedToken.ServerURL

	if cachedToken.SessionID != "" {
		reqBody := RevokeRequest{
			SessionID: cachedToken.SessionID,
		}

		jsonData, err := json.Marshal(reqBody)
		if err != nil {
			return fmt.Errorf("failed to marshal request: %w", err)
		}

		req, err := http.NewRequest("POST", serverURL+"/revoke", bytes.NewBuffer(jsonData))
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+cachedToken.IDToken)

		resp, err := httpClient.Do(req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to contact server: %v\n", err)
			fmt.Fprintf(os.Stderr, "Local cache will still be cleared.\n")
		} else {
			_ = resp.Body.Close()
			if resp.StatusCode != 200 {
				fmt.Fprintf(os.Stderr, "Warning: server returned status %d\n", resp.StatusCode)
			}
		}
	}

	if err := storage.Save(&token.Cache{ServerURL: serverURL}); err != nil {
		return fmt.Errorf("failed to clear local cache: %w", err)
	}

	fmt.Println("Logged out successfully.")
	return nil
}
