package cmd

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show authentication status",
	RunE:  runStatus,
}

func init() {
	rootCmd.AddCommand(statusCmd)
}

func runStatus(cmd *cobra.Command, args []string) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	cacheDir := filepath.Join(homeDir, ".kube", "cache")
	tokenCachePath := filepath.Join(cacheDir, "kauth-token-cache.json")
	refreshTokenPath := filepath.Join(cacheDir, "kauth-refresh-token")
	serverURLPath := filepath.Join(cacheDir, "kauth-server-url")

	if _, err := os.Stat(refreshTokenPath); os.IsNotExist(err) {
		fmt.Printf("\n  %s %s\n", errorIcon, muted.Render("Not authenticated"))
		fmt.Printf("\n  Run %s to authenticate.\n\n", accent.Render("kauth login"))
		return nil
	}

	serverURL := "unknown"
	serverURLFull := ""
	if data, err := os.ReadFile(serverURLPath); err == nil {
		serverURLFull = strings.TrimSpace(string(data))
		serverURL = urlHost(serverURLFull)
	}

	var cache *TokenCache
	if data, err := os.ReadFile(tokenCachePath); err == nil {
		cache = &TokenCache{}
		if err := json.Unmarshal(data, cache); err != nil {
			cache = nil
		}
	}

	fmt.Printf("\n  %s %s\n\n", accent.Render("●"), bold.Render("Authentication Status"))

	if cache != nil {
		user := getUserFromToken(cache.IDToken)
		fmt.Printf("  %s %s\n", accent.Render("User"), orange.Render(user))
	}

	kubeInfo, err := getKubeconfigInfo()
	if err == nil {
		fmt.Printf("  %s %s\n", accent.Render("Cluster"), orange.Render(kubeInfo.clusterName))
		fmt.Printf("  %s %s\n", accent.Render("Context"), orange.Render(kubeInfo.contextName))
		fmt.Printf("  %s %s\n", accent.Render("API Server"), orange.Render(kubeInfo.apiServer))
	}

	if cache != nil && kubeInfo != nil {
		user := getUserFromToken(cache.IDToken)
		groups := getGroupsFromToken(cache.IDToken)
		roles := getClusterRoles(kubeInfo.apiServer, cache.IDToken, user, groups)
		if len(roles) > 0 {
			fmt.Printf("  %s %s\n", accent.Render("Roles"), orange.Render(strings.Join(roles, ", ")))
		}
	}

	fmt.Printf("  %s %s\n", accent.Render("Server"), orange.Render(serverURL))

	reachable, latency := checkServerReachable(serverURLFull)
	if reachable {
		fmt.Printf("  %s %s %s %s\n", accent.Render("Health"), successIcon, green.Render("Reachable"), muted.Render(fmt.Sprintf("(%s)", latency.Round(time.Millisecond))))
	} else {
		fmt.Printf("  %s %s %s\n", accent.Render("Health"), errorIcon, red.Render("Unreachable"))
	}

	if cache == nil {
		fmt.Printf("  %s %s\n", accent.Render("Token"), muted.Render("Not yet fetched"))
	} else {
		now := time.Now()
		timeUntilExpiry := cache.ExpiresAt.Sub(now)
		expired := timeUntilExpiry <= 0

		if expired {
			fmt.Printf("  %s %s %s %s\n", accent.Render("Token"), errorIcon, red.Render("Expired"), muted.Render(fmt.Sprintf("(%s ago)", formatDuration(-timeUntilExpiry))))
		} else {
			fmt.Printf("  %s %s %s %s\n", accent.Render("Token"), successIcon, green.Render("Valid"), muted.Render(fmt.Sprintf("(expires in %s)", formatDuration(timeUntilExpiry))))
		}
	}

	fmt.Printf("  %s %s %s\n", accent.Render("Refresh"), successIcon, green.Render("Available"))

	fmt.Println()

	if kubeInfo == nil {
		fmt.Printf("  %s %s\n", warningIcon, yellow.Render("Kubeconfig not found or invalid."))
	} else {
		fmt.Printf("  %s %s\n", successIcon, green.Render("kubectl ready."))
	}

	if cache == nil {
		fmt.Printf("  %s %s\n", infoIcon, orange.Render("Token will be fetched on next kubectl use."))
	} else {
		now := time.Now()
		timeUntilExpiry := cache.ExpiresAt.Sub(now)
		expired := timeUntilExpiry <= 0

		if expired {
			fmt.Printf("  %s %s\n", infoIcon, yellow.Render("Token expired — will auto-refresh on next kubectl use."))
		} else if timeUntilExpiry < 5*time.Minute {
			fmt.Printf("  %s %s\n", warningIcon, yellow.Render("Token expires soon."))
		}
	}

	fmt.Println()
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

func decodeJWTClaims(token string) map[string]interface{} {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil
	}

	return claims
}

func getUserFromToken(token string) string {
	claims := decodeJWTClaims(token)
	if claims == nil {
		return "unknown"
	}

	if email, ok := claims["email"].(string); ok && email != "" {
		return email
	}
	if sub, ok := claims["sub"].(string); ok && sub != "" {
		return sub
	}
	return "unknown"
}

func getGroupsFromToken(token string) []string {
	claims := decodeJWTClaims(token)
	if claims == nil {
		return nil
	}

	groups, ok := claims["groups"].([]interface{})
	if !ok {
		return nil
	}

	var result []string
	for _, g := range groups {
		if s, ok := g.(string); ok {
			result = append(result, s)
		}
	}
	return result
}

func getClusterRoles(apiServer, token string, userEmail string, userGroups []string) []string {
	client := &http.Client{Timeout: 5 * time.Second}

	var roles []string

	// Check ClusterRoleBindings
	req, _ := http.NewRequest("GET", apiServer+"/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}

	if resp.StatusCode == http.StatusOK {
		var result struct {
			Items []struct {
				RoleRef struct {
					Name string `json:"name"`
				} `json:"roleRef"`
				Subjects []struct {
					Kind string `json:"kind"`
					Name string `json:"name"`
				} `json:"subjects"`
			} `json:"items"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err == nil {
			for _, binding := range result.Items {
				for _, subject := range binding.Subjects {
					if subject.Kind == "User" && subject.Name == userEmail {
						roles = append(roles, binding.RoleRef.Name)
						break
					}
					if subject.Kind == "Group" {
						for _, g := range userGroups {
							if subject.Name == g {
								roles = append(roles, binding.RoleRef.Name)
								break
							}
						}
					}
				}
			}
		}
	}
	_ = resp.Body.Close()

	return roles
}

type kubeconfigStatus struct {
	clusterName string
	apiServer   string
	contextName string
}

func getKubeconfigInfo() (*kubeconfigStatus, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	kubeconfigPath := filepath.Join(homeDir, ".kube", "config")
	data, err := os.ReadFile(kubeconfigPath)
	if err != nil {
		return nil, err
	}

	var kc kubeconfig
	if err := yaml.Unmarshal(data, &kc); err != nil {
		return nil, err
	}

	kauthUsers := make(map[string]bool)
	for _, u := range kc.Users {
		if u.User.Exec != nil && u.User.Exec.Command == "kauth" {
			kauthUsers[u.Name] = true
		}
	}

	for _, ctx := range kc.Contexts {
		if kauthUsers[ctx.Context.User] {
			for _, cluster := range kc.Clusters {
				if cluster.Name == ctx.Context.Cluster {
					return &kubeconfigStatus{
						clusterName: cluster.Name,
						apiServer:   cluster.Cluster.Server,
						contextName: ctx.Name,
					}, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("no kauth context found")
}

func checkServerReachable(serverURL string) (bool, time.Duration) {
	if serverURL == "unknown" {
		return false, 0
	}

	start := time.Now()
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(serverURL + "/info")
	elapsed := time.Since(start)

	if err != nil {
		return false, elapsed
	}
	ok := resp.StatusCode == http.StatusOK
	_ = resp.Body.Close()
	return ok, elapsed
}
