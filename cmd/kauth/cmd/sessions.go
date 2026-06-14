package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"kauth/pkg/token"

	"charm.land/lipgloss/v2"
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
	SessionID   string    `json:"sessionID"`
	UserID      string    `json:"user_id"`
	Email       string    `json:"email"`
	Username    string    `json:"username"`
	Phase       string    `json:"phase"`
	CreatedAt   time.Time `json:"created_at"`
	LastUsed    time.Time `json:"last_used"`
	RevokedAt   time.Time `json:"revoked_at"`
	CompletedAt time.Time `json:"completed_at"`
}

type SessionsResponse struct {
	Sessions []SessionInfo `json:"sessions"`
}

type RevokeSessionRequest struct {
	SessionID string `json:"session_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`
}

func runSessions(cmd *cobra.Command, args []string) error {
	storage := token.NewStorage(token.DefaultCachePath())
	cachedToken, _ := storage.Load()

	if cachedToken == nil || cachedToken.IDToken == "" {
		return fmt.Errorf("no valid token found.\n\nTo authenticate, run:\n  kauth login --url <server-url>")
	}

	serverURL := cachedToken.ServerURL
	if serverURL == "" {
		return fmt.Errorf("not authenticated.\n\nTo authenticate, run:\n  kauth login --url <server-url>")
	}

	if revokeSessionID != "" {
		return revokeSession(serverURL, revokeSessionID, cachedToken.IDToken)
	}

	var userEmail string
	claims := decodeJWTClaims(cachedToken.IDToken)
	if email, ok := claims["email"].(string); ok {
		userEmail = email
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
		fmt.Printf("\n  %s %s\n", infoIcon, muted.Render("No active sessions found."))
		return nil
	}

	serverLink := hyperlink(muted.Render(urlHost(serverURL)), serverURL)
	fmt.Printf("\n  %s %s %s\n", accent.Render("◆"), accent.Render("Sessions"), serverLink)
	fmt.Println()
	printSessions(sessionsResp.Sessions)
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

	fmt.Printf("\n  %s %s\n", successIcon, muted.Render(fmt.Sprintf("Session %s revoked.", sessionID)))
	return nil
}

func phaseStyle(phase string) lipgloss.Style {
	switch phase {
	case "Active":
		return green
	case "Revoked":
		return red
	case "Expired":
		return yellow
	case "Pending":
		return orange
	default:
		return muted
	}
}

func printSessions(sessions []SessionInfo) {
	for _, s := range sessions {
		user := s.Username
		if user == "" {
			user = s.Email
		}

		phase := phaseStyle(s.Phase).Render(s.Phase)
		lastUsed := "never"
		if !s.LastUsed.IsZero() {
			lastUsed = formatTimeAgo(s.LastUsed)
		}

		fmt.Printf("  %s %s\n", accent.Render("◆"), bold.Render(s.SessionID))
		fmt.Printf("    %s %s  %s %s  %s %s\n",
			muted.Render("phase:"), phase,
			muted.Render("user:"), user,
			muted.Render("last used:"), lastUsed,
		)
		fmt.Printf("    %s %s\n",
			muted.Render("created:"), formatTimeAgo(s.CreatedAt),
		)
		fmt.Println()
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
