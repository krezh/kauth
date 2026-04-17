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
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var serverURL string

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with Kubernetes cluster",
	Long: `Authenticate with your Kubernetes cluster.

Just provide the service URL and everything else is automatic.`,
	RunE: runLogin,
}

func init() {
	rootCmd.AddCommand(loginCmd)
	loginCmd.Flags().StringVar(&serverURL, "url", "", "kauth service URL (e.g. https://kauth.example.com)")
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
	// Determine server URL
	if serverURL == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("❌ Failed to get home directory: %w", err)
		}
		serverURLPath := filepath.Join(homeDir, ".kube", "cache", "kauth-server-url")
		serverURLBytes, err := os.ReadFile(serverURLPath)
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("❌ No server URL specified.\n\nTo authenticate, run:\n  kauth login --url <server-url>\n\nExample:\n  kauth login --url https://kauth.example.com")
			}
			return fmt.Errorf("❌ Failed to read cached server URL: %w", err)
		}
		serverURL = strings.TrimSpace(string(serverURLBytes))
		if serverURL == "" {
			return fmt.Errorf("❌ Cached server URL is empty.\n\nTo re-authenticate, run:\n  kauth login --url <server-url>")
		}
	}
	// Create HTTP client with cookie jar for session affinity
	jar, err := cookiejar.New(nil)
	if err != nil {
		return fmt.Errorf("failed to create cookie jar: %w", err)
	}
	client := &http.Client{
		Jar: jar,
	}

	// Fetch service info
	fmt.Printf("🔗 Connecting to %s...\n", serverURL)

	resp, err := client.Get(serverURL + "/info")
	if err != nil {
		return fmt.Errorf("❌ Failed to connect to kauth service.\n\nError: %w\n\nPlease check:\n  - Is the URL correct? (%s)\n  - Is the service running?\n  - Can you reach it from your network?", err, serverURL)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("❌ Service returned error: %s\n\nThe kauth service at %s is not responding correctly.", resp.Status, serverURL)
	}

	var info InfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return fmt.Errorf("❌ Failed to parse service response: %w\n\nThe service may be misconfigured or running an incompatible version.", err)
	}

	fmt.Printf("📦 Cluster: %s\n", info.ClusterName)
	fmt.Printf("🔐 Opening browser for authentication...\n\n")

	// Start login flow
	loginResp, err := client.Get(serverURL + "/start-login")
	if err != nil {
		return fmt.Errorf("❌ Failed to start login flow: %w\n\nThe service may be temporarily unavailable.", err)
	}
	defer func() { _ = loginResp.Body.Close() }()

	var loginData StartLoginResponse
	if err := json.NewDecoder(loginResp.Body).Decode(&loginData); err != nil {
		return fmt.Errorf("❌ Failed to parse login response: %w\n\nThe service may be misconfigured.", err)
	}

	// Open browser
	if err := openBrowser(loginData.LoginURL); err != nil {
		fmt.Fprintf(os.Stderr, "Could not open browser: %v\n", err)
		fmt.Printf("\nPlease visit this URL manually:\n%s\n\n", loginData.LoginURL)
	} else {
		fmt.Printf("If browser doesn't open, visit:\n%s\n\n", loginData.LoginURL)
	}

	fmt.Printf("⏳ Waiting for authentication to complete...\n")

	// Watch for completion via SSE
	status, err := watchForCompletion(client, serverURL, loginData.SessionToken)
	if err != nil {
		return err
	}

	// Save kubeconfig
	kubeconfigPath := filepath.Join(os.Getenv("HOME"), ".kube", "config")

	if err := os.MkdirAll(filepath.Dir(kubeconfigPath), 0755); err != nil {
		return fmt.Errorf("❌ Failed to create .kube directory: %w\n\nPlease check file permissions in your home directory.", err)
	}

	// Check if kubeconfig already exists and has content
	shouldMerge := false
	if existingData, err := os.ReadFile(kubeconfigPath); err == nil && len(existingData) > 0 {
		// Existing kubeconfig found, ask user what to do
		fmt.Printf("\n⚠️  Existing kubeconfig found at: %s\n", kubeconfigPath)
		fmt.Println("\nWhat would you like to do?")
		fmt.Println("  [m] Merge - Add new cluster alongside existing configs (recommended)")
		fmt.Println("  [o] Overwrite - Replace entire kubeconfig file")
		fmt.Println("  [c] Cancel - Abort without saving")
		fmt.Print("\nChoice (m/o/c): ")

		reader := bufio.NewReader(os.Stdin)
		choice, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("❌ Failed to read input: %w", err)
		}
		choice = strings.TrimSpace(strings.ToLower(choice))

		switch choice {
		case "m", "merge", "":
			shouldMerge = true
		case "o", "overwrite":
			shouldMerge = false
		case "c", "cancel":
			fmt.Println("\n❌ Cancelled. Kubeconfig not saved.")
			return nil
		default:
			return fmt.Errorf("❌ Invalid choice: '%s'\n\nPlease choose 'm' (merge), 'o' (overwrite), or 'c' (cancel).", choice)
		}
	}

	if shouldMerge {
		// Merge with existing kubeconfig
		if err := mergeKubeconfig(kubeconfigPath, status.Kubeconfig); err != nil {
			return fmt.Errorf("❌ Failed to merge kubeconfig: %w\n\nYour existing kubeconfig has not been modified.", err)
		}
		fmt.Printf("\n✅ Kubeconfig merged successfully!\n")
	} else {
		// Overwrite entire file
		if err := os.WriteFile(kubeconfigPath, []byte(status.Kubeconfig), 0600); err != nil {
			return fmt.Errorf("❌ Failed to save kubeconfig: %w\n\nPlease check file permissions.", err)
		}
		fmt.Printf("\n✅ Kubeconfig saved!\n")
	}

	// Save refresh token and server URL
	cacheDir := filepath.Join(os.Getenv("HOME"), ".kube", "cache")
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		return fmt.Errorf("❌ Failed to create cache directory: %w\n\nPlease check file permissions.", err)
	}

	if status.RefreshToken != "" {
		refreshTokenPath := filepath.Join(cacheDir, "kauth-refresh-token")
		if err := os.WriteFile(refreshTokenPath, []byte(status.RefreshToken), 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to save refresh token: %v\n", err)
		}
	}

	// Save server URL so we can reuse it later
	serverURLPath := filepath.Join(cacheDir, "kauth-server-url")
	if err := os.WriteFile(serverURLPath, []byte(serverURL), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to save server URL: %v\n", err)
	}

	fmt.Printf("✅ Kubeconfig location: %s\n", kubeconfigPath)
	fmt.Printf("✅ Authentication successful!\n")

	return nil
}

func watchForCompletion(client *http.Client, baseURL, sessionToken string) (*StatusResponse, error) {
	resp, err := client.Get(fmt.Sprintf("%s/watch?session_token=%s", baseURL, sessionToken))
	if err != nil {
		return nil, fmt.Errorf("❌ Failed to connect to watch endpoint: %w\n\nThe service may have become unavailable.", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("❌ Watch endpoint returned error: %s\n\nYour session may have expired. Please try logging in again.", resp.Status)
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
				return nil, fmt.Errorf("❌ Authentication failed: %s\n\nPlease try logging in again.", status.Error)
			}

			if status.Ready && status.Kubeconfig != "" {
				return &status, nil
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("❌ Error reading authentication stream: %w\n\nThe connection may have been interrupted.", err)
	}

	return nil, fmt.Errorf("❌ Authentication stream ended unexpectedly.\n\nThe service may have restarted. Please try logging in again.")
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
	APIVersion     string          `yaml:"apiVersion"`
	Kind           string          `yaml:"kind"`
	CurrentContext string          `yaml:"current-context,omitempty"`
	Clusters       []namedCluster  `yaml:"clusters"`
	Contexts       []namedContext  `yaml:"contexts"`
	Users          []namedUser     `yaml:"users"`
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
	Exec                 *execConfig           `yaml:"exec,omitempty"`
	Token                string                `yaml:"token,omitempty"`
	ClientCertificate    string                `yaml:"client-certificate,omitempty"`
	ClientKey            string                `yaml:"client-key,omitempty"`
	ClientCertificateData string               `yaml:"client-certificate-data,omitempty"`
	ClientKeyData        string                `yaml:"client-key-data,omitempty"`
	AuthProvider         *authProviderConfig   `yaml:"auth-provider,omitempty"`
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
