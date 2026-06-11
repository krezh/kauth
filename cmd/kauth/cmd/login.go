package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var serverURL string

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with Kubernetes cluster",
	Long: `Authenticate with your Kubernetes cluster.

Clusters are discovered automatically via DNS TXT records at _kauth.<domain>.
If no DNS records are found, the previously used server URL is tried.`,
	RunE: runLogin,
}

func init() {
	rootCmd.AddCommand(loginCmd)
	loginCmd.Flags().StringVar(&serverURL, "url", "", "kauth server URL (skips DNS discovery)")
}

type InfoResponse struct {
	ClusterName   string `json:"cluster_name"`
	ClusterServer string `json:"cluster_server"`
	IssuerURL     string `json:"issuer_url"`
	ClientID      string `json:"client_id"`
	LoginURL      string `json:"login_url"`
	RefreshURL    string `json:"refresh_url"`
}

type StartLoginResponse struct {
	SessionToken string `json:"session_token"`
	LoginURL     string `json:"login_url"`
}

type StatusResponse struct {
	Ready        bool   `json:"ready"`
	Kubeconfig   string `json:"kubeconfig,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Error        string `json:"error,omitempty"`
}

func runLogin(cmd *cobra.Command, args []string) error {
	serverURL, err := resolveServerURL()
	if err != nil {
		return err
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		return fmt.Errorf("failed to create cookie jar: %w", err)
	}
	client := &http.Client{Jar: jar}

	resp, err := client.Get(serverURL + "/info")
	if err != nil {
		return fmt.Errorf("could not reach kauth at %s: %w", serverURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned %s", resp.Status)
	}

	var info InfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return fmt.Errorf("invalid response from server: %w", err)
	}

	serverLink := hyperlink(muted.Render(urlHost(serverURL)), serverURL)
	fmt.Printf("\n  %s %s %s\n\n", accent.Render("◆"), accent.Render(info.ClusterName), serverLink)

	loginResp, err := client.Get(serverURL + "/start-login")
	if err != nil {
		return fmt.Errorf("failed to start login: %w", err)
	}
	defer func() { _ = loginResp.Body.Close() }()

	var loginData StartLoginResponse
	if err := json.NewDecoder(loginResp.Body).Decode(&loginData); err != nil {
		return fmt.Errorf("invalid login response: %w", err)
	}

	loginLink := hyperlink(link.Render("login page"), loginData.LoginURL)
	if err := openBrowser(loginData.LoginURL); err != nil {
		fmt.Printf("  %s %s %s\n\n", accent.Render("◐"), muted.Render("Open"), loginLink)
	} else {
		fmt.Printf("  %s %s %s\n", accent.Render("◐"), muted.Render("Opening browser… didn't open?"), loginLink)
	}

	fmt.Printf("  %s %s\n", accent.Render("◌"), muted.Render("Waiting for authentication…"))

	status, err := watchForCompletion(client, serverURL, loginData.SessionToken)
	if err != nil {
		return err
	}

	kubeconfigPath := filepath.Join(os.Getenv("HOME"), ".kube", "config")
	if err := os.MkdirAll(filepath.Dir(kubeconfigPath), 0755); err != nil {
		return fmt.Errorf("failed to create .kube directory: %w", err)
	}

	fileExists := false
	shouldMerge := false
	if existingData, err := os.ReadFile(kubeconfigPath); err == nil && len(existingData) > 0 {
		fileExists = true
		if hasConflict(existingData, info.ClusterName) {
			fmt.Printf("\n  %s %s\n", warningIcon, muted.Render(fmt.Sprintf("Context %q already exists", info.ClusterName)))
			choice, err := promptMenu([]promptOption{
				{key: "m", label: "merge"},
				{key: "o", label: "overwrite"},
				{key: "c", label: "cancel"},
			}, "  ")
			if err != nil {
				if err.Error() == "interrupted" {
					return nil
				}
				return err
			}
			switch choice {
			case "m":
				shouldMerge = true
			case "o":
				shouldMerge = false
			case "c":
				return nil
			}
		} else {
			shouldMerge = true
		}
	}

	if shouldMerge && fileExists {
		if err := mergeKubeconfig(kubeconfigPath, status.Kubeconfig); err != nil {
			return fmt.Errorf("failed to merge kubeconfig: %w", err)
		}
	} else {
		if err := os.WriteFile(kubeconfigPath, []byte(status.Kubeconfig), 0600); err != nil {
			return fmt.Errorf("failed to save kubeconfig: %w", err)
		}
	}

	cacheDir := filepath.Join(os.Getenv("HOME"), ".kube", "cache")
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	if status.RefreshToken != "" {
		refreshTokenPath := filepath.Join(cacheDir, "kauth-refresh-token")
		if err := os.WriteFile(refreshTokenPath, []byte(status.RefreshToken), 0600); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to save refresh token: %v\n", err)
		}

		refreshResp, err := refreshTokenFromServer(serverURL, status.RefreshToken)
		if err == nil {
			tokenCachePath := filepath.Join(cacheDir, "kauth-token-cache.json")
			expiresAt := time.Now().Add(time.Duration(refreshResp.ExpiresIn) * time.Second)
			newCache := TokenCache{
				IDToken:           refreshResp.IDToken,
				KauthRefreshToken: refreshResp.RefreshToken,
				ExpiresAt:         expiresAt,
			}
			if err := saveTokenCache(tokenCachePath, &newCache); err != nil {
				fmt.Fprintf(os.Stderr, "warning: failed to cache token: %v\n", err)
			}
		}
	}

	serverURLPath := filepath.Join(cacheDir, "kauth-server-url")
	if err := os.WriteFile(serverURLPath, []byte(serverURL), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to save server URL: %v\n", err)
	}

	fmt.Printf("\n  %s %s %s\n", successIcon, green.Render("Logged in to "+info.ClusterName), muted.Render(kubeconfigPath))

	return nil
}

func resolveServerURL() (string, error) {
	if serverURL != "" {
		return serverURL, nil
	}

	if domain, err := detectDomain(); err == nil {
		for d := domain; strings.Contains(d, "."); d = d[strings.Index(d, ".")+1:] {
			if servers := discoverDNS(d); len(servers) > 0 {
				return selectServer(servers)
			}
		}
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}
	cached := filepath.Join(homeDir, ".kube", "cache", "kauth-server-url")
	data, err := os.ReadFile(cached)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("no kauth servers found.\n\nConfigure DNS TXT records at _kauth.<domain> or re-run with a cached session.")
		}
		return "", fmt.Errorf("failed to read cached server URL: %w", err)
	}
	url := strings.TrimSpace(string(data))
	if url == "" {
		return "", fmt.Errorf("cached server URL is empty")
	}
	return url, nil
}

func selectServer(servers []discoveredServer) (string, error) {
	if len(servers) == 1 {
		return servers[0].URL, nil
	}

	fmt.Printf("\n  %s\n", muted.Render("Multiple kauth servers found"))
	opts := make([]promptOption, len(servers))
	for i, s := range servers {
		name := s.Name
		if name == "" {
			name = urlHost(s.URL)
		}
		opts[i] = promptOption{
			key:   fmt.Sprintf("%d", i+1),
			label: name,
		}
	}

	choice, err := promptMenu(opts, "  ")
	if err != nil {
		return "", err
	}
	n, _ := strconv.Atoi(choice)
	return servers[n-1].URL, nil
}

func watchForCompletion(client *http.Client, baseURL, sessionToken string) (*StatusResponse, error) {
	resp, err := client.Get(fmt.Sprintf("%s/watch?session_token=%s", baseURL, sessionToken))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to watch endpoint: %w\n\nThe service may have become unavailable", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("watch endpoint returned error: %s\n\nYour session may have expired. Please try logging in again", resp.Status)
	}

	// Read SSE stream
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()

		// SSE format: "data: <json>"
		if data, ok := strings.CutPrefix(line, "data: "); ok {
			var status StatusResponse
			if err := json.Unmarshal([]byte(data), &status); err != nil {
				continue
			}

			if status.Error != "" {
				return nil, fmt.Errorf("authentication failed: %s\n\nPlease try logging in again", status.Error)
			}

			if status.Ready && status.Kubeconfig != "" {
				return &status, nil
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading authentication stream: %w\n\nThe connection may have been interrupted", err)
	}

	return nil, fmt.Errorf("authentication stream ended unexpectedly.\n\nThe service may have restarted. Please try logging in again")
}

func openBrowser(url string) error {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
		args = []string{url}
	case "linux":
		for _, c := range []string{"xdg-open", "x-www-browser", "www-browser"} {
			if err := exec.Command(c, url).Start(); err == nil {
				return nil
			}
		}
		return fmt.Errorf("could not find a browser to open")
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}

	return exec.Command(cmd, args...).Start()
}

// Kubeconfig structures for parsing and merging
type kubeconfig struct {
	APIVersion     string         `yaml:"apiVersion"`
	Kind           string         `yaml:"kind"`
	CurrentContext string         `yaml:"current-context,omitempty"`
	Clusters       []namedCluster `yaml:"clusters"`
	Contexts       []namedContext `yaml:"contexts"`
	Users          []namedUser    `yaml:"users"`
}

type namedCluster struct {
	Name    string  `yaml:"name"`
	Cluster cluster `yaml:"cluster"`
}

type cluster struct {
	Server                   string `yaml:"server"`
	CertificateAuthorityData string `yaml:"certificate-authority-data,omitempty"`
	CertificateAuthority     string `yaml:"certificate-authority,omitempty"`
	InsecureSkipTLSVerify    bool   `yaml:"insecure-skip-tls-verify,omitempty"`
}

type namedContext struct {
	Name    string  `yaml:"name"`
	Context context `yaml:"context"`
}

type context struct {
	Cluster   string `yaml:"cluster"`
	User      string `yaml:"user"`
	Namespace string `yaml:"namespace,omitempty"`
}

type namedUser struct {
	Name string `yaml:"name"`
	User user   `yaml:"user"`
}

type user struct {
	Exec                  *execConfig         `yaml:"exec,omitempty"`
	Token                 string              `yaml:"token,omitempty"`
	ClientCertificate     string              `yaml:"client-certificate,omitempty"`
	ClientKey             string              `yaml:"client-key,omitempty"`
	ClientCertificateData string              `yaml:"client-certificate-data,omitempty"`
	ClientKeyData         string              `yaml:"client-key-data,omitempty"`
	AuthProvider          *authProviderConfig `yaml:"auth-provider,omitempty"`
}

type execConfig struct {
	APIVersion      string   `yaml:"apiVersion"`
	Command         string   `yaml:"command"`
	Args            []string `yaml:"args"`
	Env             []envVar `yaml:"env,omitempty"`
	InteractiveMode string   `yaml:"interactiveMode,omitempty"`
}

type envVar struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
}

type authProviderConfig struct {
	Name   string            `yaml:"name"`
	Config map[string]string `yaml:"config,omitempty"`
}

func hasConflict(data []byte, clusterName string) bool {
	var kc kubeconfig
	if err := yaml.Unmarshal(data, &kc); err != nil {
		return false
	}
	suffix := "@" + clusterName
	for _, c := range kc.Contexts {
		if c.Name == clusterName || strings.HasSuffix(c.Name, suffix) {
			return true
		}
	}
	for _, c := range kc.Clusters {
		if c.Name == clusterName {
			return true
		}
	}
	for _, u := range kc.Users {
		if u.Name == clusterName {
			return true
		}
	}
	return false
}

func mergeKubeconfig(existingPath, newConfigYAML string) error {
	// Parse existing kubeconfig
	existingData, err := os.ReadFile(existingPath)
	if err != nil {
		return fmt.Errorf("failed to read existing kubeconfig: %w", err)
	}

	var existing kubeconfig
	if err := yaml.Unmarshal(existingData, &existing); err != nil {
		return fmt.Errorf("failed to parse existing kubeconfig (may be invalid YAML): %w", err)
	}

	// Parse new kubeconfig
	var newConfig kubeconfig
	if err := yaml.Unmarshal([]byte(newConfigYAML), &newConfig); err != nil {
		return fmt.Errorf("failed to parse new kubeconfig from server: %w", err)
	}

	// Merge clusters (upsert by name)
	for _, newCluster := range newConfig.Clusters {
		found := false
		for i, existingCluster := range existing.Clusters {
			if existingCluster.Name == newCluster.Name {
				existing.Clusters[i] = newCluster
				found = true
				break
			}
		}
		if !found {
			existing.Clusters = append(existing.Clusters, newCluster)
		}
	}

	// Merge users (upsert by name)
	for _, newUser := range newConfig.Users {
		found := false
		for i, existingUser := range existing.Users {
			if existingUser.Name == newUser.Name {
				existing.Users[i] = newUser
				found = true
				break
			}
		}
		if !found {
			existing.Users = append(existing.Users, newUser)
		}
	}

	// Merge contexts (upsert by name)
	for _, newContext := range newConfig.Contexts {
		found := false
		for i, existingContext := range existing.Contexts {
			if existingContext.Name == newContext.Name {
				existing.Contexts[i] = newContext
				found = true
				break
			}
		}
		if !found {
			existing.Contexts = append(existing.Contexts, newContext)
		}
	}

	// Update current-context to the new one
	if newConfig.CurrentContext != "" {
		existing.CurrentContext = newConfig.CurrentContext
	}

	// Save merged kubeconfig
	mergedData, err := yaml.Marshal(&existing)
	if err != nil {
		return fmt.Errorf("failed to marshal merged kubeconfig: %w", err)
	}

	if err := os.WriteFile(existingPath, mergedData, 0600); err != nil {
		return fmt.Errorf("failed to write merged kubeconfig (check permissions): %w", err)
	}

	return nil
}
