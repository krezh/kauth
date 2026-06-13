package cmd

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"kauth/pkg/token"

	"gopkg.in/yaml.v3"

	"github.com/spf13/cobra"
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
	storage := token.NewStorage(token.DefaultCachePath())

	cachedToken, _ := storage.Load()
	if cachedToken == nil || cachedToken.RefreshToken == "" {
		fmt.Printf("\n  %s %s\n", errorIcon, muted.Render("Not authenticated"))
		fmt.Printf("\n  Run %s to authenticate.\n\n", accent.Render("kauth login"))
		return nil
	}

	serverURLFull := cachedToken.ServerURL
	serverURL := "unknown"
	if serverURLFull != "" {
		serverURL = urlHost(serverURLFull)
	}

	fmt.Printf("\n  %s %s\n\n", accent.Render("●"), bold.Render("Authentication Status"))

	user := getUserFromToken(cachedToken.IDToken)
	fmt.Printf("  %s %s\n", accent.Render("User"), orange.Render(user))

	kubeInfo, err := getKubeconfigInfo()
	if err == nil {
		fmt.Printf("  %s %s\n", accent.Render("Cluster"), orange.Render(kubeInfo.clusterName))
		fmt.Printf("  %s %s\n", accent.Render("Context"), orange.Render(kubeInfo.contextName))
		fmt.Printf("  %s %s\n", accent.Render("API Server"), orange.Render(kubeInfo.apiServer))
	}

	if kubeInfo != nil {
		user := getUserFromToken(cachedToken.IDToken)
		groups := getGroupsFromToken(cachedToken.IDToken)
		roles := getClusterRoles(kubeInfo.apiServer, cachedToken.IDToken, user, groups)
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

	now := time.Now()
	timeUntilExpiry := cachedToken.Expiry.Sub(now)
	expired := timeUntilExpiry <= 0

	if expired {
		fmt.Printf("  %s %s %s %s\n", accent.Render("Token"), errorIcon, red.Render("Expired"), muted.Render(fmt.Sprintf("(%s ago)", formatDuration(-timeUntilExpiry))))
	} else {
		fmt.Printf("  %s %s %s %s\n", accent.Render("Token"), successIcon, green.Render("Valid"), muted.Render(fmt.Sprintf("(expires in %s)", formatDuration(timeUntilExpiry))))
	}

	fmt.Printf("  %s %s %s\n", accent.Render("Refresh"), successIcon, green.Render("Available"))

	fmt.Println()

	if kubeInfo == nil {
		fmt.Printf("  %s %s\n", warningIcon, yellow.Render("Kubeconfig not found or invalid."))
	} else {
		fmt.Printf("  %s %s\n", successIcon, green.Render("kubectl ready."))
	}

	now = time.Now()
	timeUntilExpiry = cachedToken.Expiry.Sub(now)
	expired = timeUntilExpiry <= 0

	if expired {
		fmt.Printf("  %s %s\n", infoIcon, yellow.Render("Token expired — will auto-refresh on next kubectl use."))
	} else if timeUntilExpiry < 5*time.Minute {
		fmt.Printf("  %s %s\n", warningIcon, yellow.Render("Token expires soon."))
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

func decodeJWTClaims(token string) map[string]any {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}

	var claims map[string]any
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

	groups, ok := claims["groups"].([]any)
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
					if subject.Kind == "Group" && slices.Contains(userGroups, subject.Name) {
						roles = append(roles, binding.RoleRef.Name)
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
