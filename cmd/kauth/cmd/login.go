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

	"kauth/pkg/token"

	"gopkg.in/yaml.v3"

	"github.com/spf13/cobra"
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
	SessionID    string `json:"session_id,omitempty"`
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

	storage := token.NewStorage(token.DefaultCachePath())
	newCache := &token.Cache{
		ServerURL: serverURL,
	}

	if status.RefreshToken != "" {
		refreshResp, err := refreshTokenFromServer(serverURL, status.RefreshToken)
		if err == nil {
			expiresAt := time.Now().Add(time.Duration(refreshResp.ExpiresIn) * time.Second)
			newCache.IDToken = refreshResp.IDToken
			newCache.RefreshToken = refreshResp.RefreshToken
			newCache.SessionID = status.SessionID
			newCache.Expiry = expiresAt
		}
	}

	if err := storage.Save(newCache); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to cache token: %v\n", err)
	}

	fmt.Printf("\n  %s %s %s\n", successIcon, green.Render("Logged in to "+info.ClusterName), muted.Render(kubeconfigPath))

	return nil
}

func resolveServerURL() (string, error) {
	if serverURL != "" {
		return serverURL, nil
	}

	if domain, err := detectDomain(); err == nil {
		for d := domain; strings.Contains(d, "."); {
			if servers := discoverDNS(d); len(servers) > 0 {
				return selectServer(servers)
			}
			_, d, _ = strings.Cut(d, ".")
		}
	}

	if cached, err := token.NewStorage(token.DefaultCachePath()).Load(); err == nil && cached != nil && cached.ServerURL != "" {
		return cached.ServerURL, nil
	}

	return "", fmt.Errorf("no kauth servers found.\n\nConfigure DNS TXT records at _kauth.<domain> or run:\n  kauth login --url <server-url>")
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

// watchForCompletion waits for the login to complete by streaming the server's
// /watch SSE endpoint. The connection is long-lived (it stays open while the
// user authenticates in the browser) so it is vulnerable to being silently
// dropped by intermediaries — VPNs and proxies can half-close the TCP socket
// without sending FIN/RST, which would otherwise block the reader forever.
//
// To stay robust, each connection is read with a liveness deadline; if no data
// (keepalive or result) arrives in time, or the stream ends without a result,
// we reconnect. This is safe because the server immediately re-sends the final
// status when the session is already active, so a reconnect recovers any result
// that was missed during a drop.
func watchForCompletion(client *http.Client, baseURL, sessionToken string) (*StatusResponse, error) {
	deadline := time.Now().Add(15 * time.Minute)
	for {
		status, retriable, err := watchOnce(client, baseURL, sessionToken)
		switch {
		case err != nil && !retriable:
			return nil, err
		case status != nil:
			return status, nil
		}

		if !time.Now().Before(deadline) {
			return nil, fmt.Errorf("timed out waiting for authentication.\n\nPlease try logging in again")
		}
		if debug {
			fmt.Fprintf(os.Stderr, "  [debug] reconnecting in 2s...\n")
		}
		time.Sleep(2 * time.Second)
	}
}

// watchOnce makes a single /watch connection. It returns a non-nil status on
// success. retriable is true when the connection dropped or idled without a
// result, signalling the caller to reconnect.
func watchOnce(client *http.Client, baseURL, sessionToken string) (status *StatusResponse, retriable bool, err error) {
	resp, err := client.Get(fmt.Sprintf("%s/watch?session_token=%s", baseURL, sessionToken))
	if err != nil {
		return nil, true, nil // connection failure: reconnect
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// 5xx may be transient (server starting / rolling update); 4xx is fatal.
		if resp.StatusCode >= 500 {
			return nil, true, nil
		}
		return nil, false, fmt.Errorf("watch endpoint returned error: %s\n\nYour session may have expired. Please try logging in again", resp.Status)
	}

	// Read the SSE stream in a goroutine so the main loop can enforce a
	// liveness deadline that the blocking Scanner cannot provide on its own.
	lines := make(chan string)
	done := make(chan struct{})
	defer close(done)
	go func() {
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			select {
			case lines <- scanner.Text():
			case <-done:
				return
			}
		}
		close(lines)
	}()

	// The server sends a keepalive every 5s; if nothing arrives within this
	// window the link is considered dead (half-open) and we reconnect.
	const readTimeout = 30 * time.Second
	timer := time.NewTimer(readTimeout)
	defer timer.Stop()

	for {
		select {
		case line, ok := <-lines:
			if !ok {
				if debug {
					fmt.Fprintf(os.Stderr, "\n  [debug] watch stream ended, reconnecting\n")
				}
				return nil, true, nil // stream ended: reconnect
			}
			if !timer.Stop() {
				<-timer.C
			}
			timer.Reset(readTimeout)

			data, ok := strings.CutPrefix(line, "data: ")
			if !ok {
				if debug {
					fmt.Fprintf(os.Stderr, ".")
				}
				continue // keepalive comment or blank line
			}
			var s StatusResponse
			if err := json.Unmarshal([]byte(data), &s); err != nil {
				continue
			}
			if s.Error != "" {
				return nil, false, fmt.Errorf("authentication failed: %s\n\nPlease try logging in again", s.Error)
			}
			if s.Ready && s.Kubeconfig != "" {
				return &s, false, nil
			}
		case <-timer.C:
			// No data within readTimeout: the connection is likely half-open.
			// Closing the body unblocks the reader goroutine; then reconnect.
			if debug {
				fmt.Fprintf(os.Stderr, "\n  [debug] 30s read timeout, reconnecting\n")
			}
			_ = resp.Body.Close()
			return nil, true, nil
		}
	}
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
