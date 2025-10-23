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
)

var serviceURL string

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with Kubernetes cluster",
	Long: `Authenticate with your Kubernetes cluster.

Just provide the service URL and everything else is automatic.`,
	RunE: runLogin,
}

func init() {
	rootCmd.AddCommand(loginCmd)
	loginCmd.Flags().StringVar(&serviceURL, "url", "", "kauth service URL (e.g. https://kauth.example.com)")
	loginCmd.MarkFlagRequired("url")
}

type InfoResponse struct {
	ClusterName   string `json:"cluster_name"`
	ClusterServer string `json:"cluster_server"`
	IssuerURL     string `json:"issuer_url"`
	ClientID      string `json:"client_id"`
	LoginURL      string `json:"login_url"`
	RefreshURL    string `json:"refresh_url"` // New: refresh endpoint
}

type StartLoginResponse struct {
	SessionToken string `json:"session_token"` // Changed from session_id to session_token (JWT)
	LoginURL     string `json:"login_url"`
}

type StatusResponse struct {
	Ready        bool   `json:"ready"`
	Kubeconfig   string `json:"kubeconfig,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"` // New: kauth refresh token
	Error        string `json:"error,omitempty"`
}

func runLogin(cmd *cobra.Command, args []string) error {
	// Create HTTP client with cookie jar for session affinity
	jar, err := cookiejar.New(nil)
	if err != nil {
		return fmt.Errorf("failed to create cookie jar: %w", err)
	}
	client := &http.Client{
		Jar: jar,
	}

	// Fetch service info
	fmt.Printf("🔗 Connecting to %s...\n", serviceURL)

	resp, err := client.Get(serviceURL + "/info")
	if err != nil {
		return fmt.Errorf("failed to connect to service: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("service returned error: %s", resp.Status)
	}

	var info InfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return fmt.Errorf("failed to parse service response: %w", err)
	}

	fmt.Printf("📦 Cluster: %s\n", info.ClusterName)
	fmt.Printf("🔐 Opening browser for authentication...\n\n")

	// Start login flow
	loginResp, err := client.Get(serviceURL + "/start-login")
	if err != nil {
		return fmt.Errorf("failed to start login: %w", err)
	}
	defer loginResp.Body.Close()

	var loginData StartLoginResponse
	if err := json.NewDecoder(loginResp.Body).Decode(&loginData); err != nil {
		return fmt.Errorf("failed to parse login response: %w", err)
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
	status, err := watchForCompletion(client, serviceURL, loginData.SessionToken)
	if err != nil {
		return err
	}

	// Save kubeconfig
	kubeconfigPath := filepath.Join(os.Getenv("HOME"), ".kube", "config")

	if err := os.MkdirAll(filepath.Dir(kubeconfigPath), 0755); err != nil {
		return fmt.Errorf("failed to create .kube directory: %w", err)
	}

	if err := os.WriteFile(kubeconfigPath, []byte(status.Kubeconfig), 0600); err != nil {
		return fmt.Errorf("failed to save kubeconfig: %w", err)
	}

	// Save refresh token and server URL
	cacheDir := filepath.Join(os.Getenv("HOME"), ".kube", "cache")
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	if status.RefreshToken != "" {
		refreshTokenPath := filepath.Join(cacheDir, "kauth-refresh-token")
		if err := os.WriteFile(refreshTokenPath, []byte(status.RefreshToken), 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to save refresh token: %v\n", err)
		}
	}

	// Save server URL so get-token can find it automatically
	serverURLPath := filepath.Join(cacheDir, "kauth-server-url")
	if err := os.WriteFile(serverURLPath, []byte(serviceURL), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to save server URL: %v\n", err)
	}

	fmt.Printf("\n✅ Authentication successful!\n")
	fmt.Printf("✅ Kubeconfig saved to: %s\n", kubeconfigPath)
	if status.RefreshToken != "" {
		fmt.Printf("✅ Refresh token saved for automatic token renewal\n")
	}
	fmt.Printf("\n🎉 You're ready to use kubectl:\n")
	fmt.Printf("   kubectl get pods\n")
	fmt.Printf("   kubectl get nodes\n\n")

	return nil
}

func watchForCompletion(client *http.Client, baseURL, sessionToken string) (*StatusResponse, error) {
	resp, err := client.Get(fmt.Sprintf("%s/watch?session_token=%s", baseURL, sessionToken))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to watch endpoint: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("watch endpoint returned error: %s", resp.Status)
	}

	// Read SSE stream
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()

		// SSE format: "data: <json>"
		if strings.HasPrefix(line, "data: ") {
			data := strings.TrimPrefix(line, "data: ")

			var status StatusResponse
			if err := json.Unmarshal([]byte(data), &status); err != nil {
				continue
			}

			if status.Error != "" {
				return nil, fmt.Errorf("authentication failed: %s", status.Error)
			}

			if status.Ready && status.Kubeconfig != "" {
				return &status, nil
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading stream: %w", err)
	}

	return nil, fmt.Errorf("stream ended unexpectedly")
}

func openBrowser(url string) error {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
		args = []string{url}
	case "windows":
		cmd = "cmd"
		args = []string{"/c", "start", "", url}
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
