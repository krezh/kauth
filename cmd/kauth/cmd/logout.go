package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

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
	storage, err := credentialStorageForCurrentContext()
	if err != nil {
		return err
	}

	cachedToken, err := storage.Load()
	if err != nil || cachedToken == nil || (cachedToken.RefreshToken == "" && cachedToken.WebhookToken == "") {
		fmt.Println("Not authenticated.")
		return nil
	}

	serverURL := cachedToken.ServerURL
	if err := ensureFreshIDToken(storage, cachedToken); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to refresh management token: %v\n", err)
	}

	if cachedToken.SessionID != "" {
		reqBody := RevokeRequest{
			SessionID: cachedToken.SessionID,
		}

		jsonData, err := json.Marshal(reqBody)
		if err != nil {
			return fmt.Errorf("failed to marshal request: %w", err)
		}

		req, err := http.NewRequest(http.MethodPost, serverURL+"/revoke", bytes.NewBuffer(jsonData))
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
			if resp.StatusCode != http.StatusOK {
				fmt.Fprintf(os.Stderr, "Warning: server returned status %d\n", resp.StatusCode)
			}
		}
	}

	if err := storage.WithLock(5*time.Second, func() error {
		current, loadErr := storage.Load()
		if loadErr != nil {
			return loadErr
		}
		if current == nil {
			return nil
		}
		if current.SessionID != cachedToken.SessionID {
			return fmt.Errorf("credentials changed during logout; the newer login was preserved")
		}
		return storage.Delete()
	}); err != nil {
		return fmt.Errorf("failed to clear local cache: %w", err)
	}
	defaultStorage := token.NewStorage(token.DefaultCachePath())
	if err := defaultStorage.WithLock(5*time.Second, func() error {
		current, loadErr := defaultStorage.Load()
		if loadErr != nil {
			return loadErr
		}
		if current != nil && current.ServerURL == serverURL && current.SessionID == cachedToken.SessionID {
			return defaultStorage.Delete()
		}
		return nil
	}); err != nil {
		return fmt.Errorf("failed to clear current-login cache: %w", err)
	}

	fmt.Println("Logged out successfully.")
	return nil
}
