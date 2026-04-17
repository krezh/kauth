package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show authentication status and token information",
	Long: `Display current authentication status including:
  - Server URL
  - Token expiry time
  - Time until expiration
  - Refresh token status`,
	RunE: runStatus,
}

func init() {
	rootCmd.AddCommand(statusCmd)
}

type tokenInfo struct {
	ServerURL    string
	TokenExpiry  time.Time
	HasRefreshToken bool
	TimeUntilExpiry time.Duration
	Expired      bool
}

func runStatus(cmd *cobra.Command, args []string) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("❌ Failed to get home directory: %w", err)
	}

	cacheDir := filepath.Join(homeDir, ".kube", "cache")
	tokenCachePath := filepath.Join(cacheDir, "kauth-token-cache.json")
	refreshTokenPath := filepath.Join(cacheDir, "kauth-refresh-token")
	serverURLPath := filepath.Join(cacheDir, "kauth-server-url")

	// Check if authenticated
	if _, err := os.Stat(tokenCachePath); os.IsNotExist(err) {
		fmt.Println("❌ Not authenticated")
		fmt.Println("\nTo authenticate, run:")
		fmt.Println("  kauth login --url <server-url>")
		return nil
	}

	// Get server URL
	serverURL := "unknown"
	if data, err := os.ReadFile(serverURLPath); err == nil {
		serverURL = string(data)
	}

	// Load token cache
	var cache TokenCache
	data, err := os.ReadFile(tokenCachePath)
	if err != nil {
		return fmt.Errorf("❌ Failed to read token cache: %w", err)
	}

	if err := json.Unmarshal(data, &cache); err != nil {
		return fmt.Errorf("❌ Failed to parse token cache: %w", err)
	}

	// Check refresh token
	hasRefreshToken := false
	if refreshData, err := os.ReadFile(refreshTokenPath); err == nil && len(refreshData) > 0 {
		hasRefreshToken = true
	}

	// Calculate time until expiry
	now := time.Now()
	timeUntilExpiry := cache.ExpiresAt.Sub(now)
	expired := timeUntilExpiry <= 0

	// Display status
	fmt.Println("🔐 Authentication Status")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("\n📍 Server:           %s\n", serverURL)

	if expired {
		fmt.Println("⏰ Token Status:      ❌ EXPIRED")
		fmt.Printf("   Expired:          %v ago\n", -timeUntilExpiry.Round(time.Second))
	} else {
		fmt.Println("⏰ Token Status:      ✅ Valid")
		fmt.Printf("   Expires At:       %s\n", cache.ExpiresAt.Local().Format(time.RFC1123))
		fmt.Printf("   Time Remaining:   %s\n", formatDuration(timeUntilExpiry))
	}

	if hasRefreshToken {
		fmt.Println("🔄 Refresh Token:    ✅ Available")
		fmt.Println("   Auto-refresh:     Enabled")
	} else {
		fmt.Println("🔄 Refresh Token:    ❌ Not available")
	}

	fmt.Println()

	if expired && !hasRefreshToken {
		fmt.Println("⚠️  Your token has expired and no refresh token is available.")
		fmt.Println("\nTo re-authenticate, run:")
		fmt.Println("  kauth login")
	} else if expired {
		fmt.Println("ℹ️  Your token has expired but will be automatically refreshed on next kubectl use.")
	} else if timeUntilExpiry < 5*time.Minute {
		fmt.Println("⚠️  Your token will expire soon!")
	}

	return nil
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)

	days := d / (24 * time.Hour)
	d -= days * 24 * time.Hour

	hours := d / time.Hour
	d -= hours * time.Hour

	minutes := d / time.Minute
	d -= minutes * time.Minute

	seconds := d / time.Second

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	} else if hours > 0 {
		return fmt.Sprintf("%dh %dm %ds", hours, minutes, seconds)
	} else if minutes > 0 {
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}
