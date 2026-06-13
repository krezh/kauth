package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"kauth/pkg/token"

	"github.com/spf13/cobra"
)

var sessionsCmd = &cobra.Command{
	Use:   "sessions",
	Short: "List active authentication sessions",
	Long:  `List all active authentication sessions for the current user.`,
	RunE:  runSessions,
}

var revokeSessionID string

func init() {
	rootCmd.AddCommand(sessionsCmd)
	sessionsCmd.Flags().StringVar(&revokeSessionID, "revoke", "", "Revoke a specific session by ID")
}

type SessionInfo struct {
	State       string    `json:"state"`
	UserID      string    `json:"user_id"`
	Email       string    `json:"email"`
	Username    string    `json:"username"`
	Phase       string    `json:"phase"`
	CreatedAt   time.Time `json:"created_at"`
	LastUsed    time.Time `json:"last_used"`
	RevokedAt   time.Time `json:"revoked_at,omitempty"`
	CompletedAt time.Time `json:"completed_at,omitempty"`
}

type SessionsResponse struct {
	Sessions []SessionInfo `json:"sessions"`
}

type RevokeSessionRequest struct {
	SessionID string `json:"session_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`
}

func runSessions(cmd *cobra.Command, args []string) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	cacheDir := filepath.Join(homeDir, ".kube", "cache")
	serverURLPath := filepath.Join(cacheDir, "kauth-server-url")

	serverURLBytes, err := os.ReadFile(serverURLPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("not authenticated.\n\nTo authenticate, run:\n  kauth login --url <server-url>")
		}
		return fmt.Errorf("failed to read server URL: %w", err)
	}
	serverURL := string(serverURLBytes)

	storage := token.NewStorage(token.DefaultCachePath())
	cachedToken, _ := storage.Load()

	if cachedToken == nil || cachedToken.IDToken == "" {
		return fmt.Errorf("no valid token found.\n\nTo authenticate, run:\n  kauth login --url <server-url>")
	}

	if revokeSessionID != "" {
		return revokeSession(serverURL, revokeSessionID, cachedToken.IDToken)
	}

	userEmail := ""
	if cachedToken != nil {
		idToken := cachedToken.IDToken
		claims := decodeJWTClaims(idToken)
		if email, ok := claims["email"].(string); ok {
			userEmail = email
		}
	}

	req, err := http.NewRequest("GET", serverURL+"/sessions", nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+cachedToken.IDToken)

	if userEmail != "" {
		q := req.URL.Query()
		q.Add("user_email", userEmail)
		req.URL.RawQuery = q.Encode()
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		return fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	var sessionsResp SessionsResponse
	if err := json.NewDecoder(resp.Body).Decode(&sessionsResp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if len(sessionsResp.Sessions) == 0 {
		fmt.Println("No active sessions found.")
		return nil
	}

	printSessionsTable(sessionsResp.Sessions)
	return nil
}

func revokeSession(serverURL, sessionID, idToken string) error {
	reqBody := RevokeSessionRequest{
		SessionID: sessionID,
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
	req.Header.Set("Authorization", "Bearer "+idToken)

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		return fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	fmt.Printf("Session %s revoked.\n", sessionID)
	return nil
}

func printSessionsTable(sessions []SessionInfo) {
	headers := []string{"STATE", "PHASE", "USER", "LAST USED", "CREATED"}
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}

	rows := make([][]string, len(sessions))
	for i, s := range sessions {
		user := s.Username
		if user == "" {
			user = s.Email
		}
		lastUsed := "never"
		if !s.LastUsed.IsZero() {
			lastUsed = formatTimeAgo(s.LastUsed)
		}
		rows[i] = []string{
			truncate(s.State, 12),
			s.Phase,
			user,
			lastUsed,
			formatTimeAgo(s.CreatedAt),
		}
		for j, cell := range rows[i] {
			if len(cell) > widths[j] {
				widths[j] = len(cell)
			}
		}
	}

	formatRow := func(cells []string) string {
		parts := make([]string, len(cells))
		for i, cell := range cells {
			parts[i] = cell + strings.Repeat(" ", widths[i]-len(cell)+2)
		}
		return strings.TrimRight(strings.Join(parts, ""), " ")
	}

	fmt.Println(formatRow(headers))
	for _, row := range rows {
		fmt.Println(formatRow(row))
	}
}

func formatTimeAgo(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		m := int(d.Minutes())
		if m == 1 {
			return "1m ago"
		}
		return fmt.Sprintf("%dm ago", m)
	case d < 24*time.Hour:
		h := int(d.Hours())
		if h == 1 {
			return "1h ago"
		}
		return fmt.Sprintf("%dh ago", h)
	default:
		days := int(d.Hours() / 24)
		if days == 1 {
			return "1d ago"
		}
		return fmt.Sprintf("%dd ago", days)
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
