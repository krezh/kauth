package cmd

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"time"

	"kauth/pkg/token"

	"github.com/spf13/cobra"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
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
	Ready         bool      `json:"ready"`
	Kubeconfig    string    `json:"kubeconfig,omitempty"`
	RefreshToken  string    `json:"refresh_token,omitempty"`
	SessionID     string    `json:"session_id,omitempty"`
	WebhookToken  string    `json:"webhook_token,omitempty"`
	SessionExpiry time.Time `json:"session_expiry,omitempty"`
	Error         string    `json:"error,omitempty"`
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
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}

	resp, err := getWithContext(cmd.Context(), client, serverURL+"/info")
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

	loginResp, err := getWithContext(cmd.Context(), client, serverURL+"/start-login")
	if err != nil {
		return fmt.Errorf("failed to start login: %w", err)
	}
	defer func() { _ = loginResp.Body.Close() }()

	var loginData StartLoginResponse
	if err := json.NewDecoder(loginResp.Body).Decode(&loginData); err != nil {
		return fmt.Errorf("invalid login response: %w", err)
	}
	if err := validateHTTPSURL(loginData.LoginURL); err != nil {
		return fmt.Errorf("unsafe login URL from server: %w", err)
	}
	client.Timeout = 0
	ctx, cancel := context.WithTimeout(cmd.Context(), 15*time.Minute)
	defer cancel()

	loginLink := hyperlink(link.Render("login page"), loginData.LoginURL)
	if err := openBrowser(loginData.LoginURL); err != nil {
		fmt.Printf("  %s %s %s\n\n", accent.Render("◐"), muted.Render("Open"), loginLink)
	} else {
		fmt.Printf("  %s %s %s\n", accent.Render("◐"), muted.Render("Opening browser… didn't open?"), loginLink)
	}

	fmt.Printf("  %s %s\n", accent.Render("◌"), muted.Render("Waiting for authentication…"))

	status, err := watchForCompletion(ctx, client, serverURL, loginData.SessionToken)
	if err != nil {
		return err
	}
	incomingConfig, err := clientcmd.Load([]byte(status.Kubeconfig))
	if err != nil {
		return fmt.Errorf("invalid kubeconfig from server: %w", err)
	}
	if err := validateRemoteKubeconfig(incomingConfig); err != nil {
		return err
	}
	profile := token.ProfileID(serverURL)
	setKubeconfigProfile(incomingConfig, profile)

	kubeconfigPath := filepath.Join(os.Getenv("HOME"), ".kube", "config")
	if err := os.MkdirAll(filepath.Dir(kubeconfigPath), 0755); err != nil {
		return fmt.Errorf("failed to create .kube directory: %w", err)
	}

	cancelled, err := updateKubeconfig(kubeconfigPath, incomingConfig, info.ClusterName)
	if err != nil {
		return err
	}
	if cancelled {
		return nil
	}

	newCache := &token.Cache{
		ServerURL:    serverURL,
		RefreshToken: status.RefreshToken,
		SessionID:    status.SessionID,
		WebhookToken: status.WebhookToken,
	}

	if !status.SessionExpiry.IsZero() {
		newCache.Expiry = status.SessionExpiry
	} else if status.WebhookToken != "" {
		// Server should always send SessionExpiry, but fall back to 7 days.
		newCache.Expiry = time.Now().Add(7 * 24 * time.Hour)
	}

	profilePath, err := token.ProfileCachePath(profile)
	if err != nil {
		return err
	}
	profileStorage := token.NewStorage(profilePath)
	if err := profileStorage.WithLock(5*time.Second, func() error { return profileStorage.Save(newCache) }); err != nil {
		return fmt.Errorf("failed to cache cluster credential: %w", err)
	}
	if status.RefreshToken != "" {
		if err := ensureFreshIDToken(profileStorage, newCache); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to get management token: %v\n", err)
		}
	}

	storage := token.NewStorage(token.DefaultCachePath())
	if err := storage.WithLock(5*time.Second, func() error { return storage.Save(newCache) }); err != nil {
		return fmt.Errorf("failed to cache current login: %w", err)
	}
	fmt.Printf("\n  %s %s %s\n", successIcon, green.Render("Logged in to "+info.ClusterName), muted.Render(kubeconfigPath))

	return nil
}

func updateKubeconfig(kubeconfigPath string, incomingConfig *clientcmdapi.Config, clusterName string) (bool, error) {
	cancelled := false
	err := token.WithFileLock(kubeconfigPath+".kauth.lock", 5*time.Minute, func() error {
		fileExists := false
		shouldMerge := false
		if existingData, err := os.ReadFile(kubeconfigPath); err == nil && len(existingData) > 0 {
			fileExists = true
			if hasConflict(existingData, incomingConfig) {
				fmt.Printf("\n  %s %s\n", warningIcon, muted.Render(fmt.Sprintf("Context %q already exists", clusterName)))
				choice, err := promptMenu([]promptOption{
					{key: "m", label: "merge"},
					{key: "o", label: "overwrite"},
					{key: "c", label: "cancel"},
				}, "  ")
				if err != nil {
					if err.Error() == "interrupted" {
						cancelled = true
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
					cancelled = true
					return nil
				}
			} else {
				shouldMerge = true
			}
		}

		if shouldMerge && fileExists {
			if err := mergeKubeconfig(kubeconfigPath, incomingConfig); err != nil {
				return fmt.Errorf("failed to merge kubeconfig: %w", err)
			}
		} else if err := writeKubeconfigAtomic(kubeconfigPath, incomingConfig); err != nil {
			return fmt.Errorf("failed to save kubeconfig: %w", err)
		}
		return nil
	})
	return cancelled, err
}

func setKubeconfigProfile(config *clientcmdapi.Config, profile string) {
	renamed := make(map[string]string, len(config.AuthInfos))
	profiledAuthInfos := make(map[string]*clientcmdapi.AuthInfo, len(config.AuthInfos))
	for name, authInfo := range config.AuthInfos {
		if authInfo != nil && authInfo.Exec != nil {
			authInfo.Exec.Args = []string{"get-token", "--profile", profile}
		}
		profiledName := name + "@" + profile
		profiledAuthInfos[profiledName] = authInfo
		renamed[name] = profiledName
	}
	config.AuthInfos = profiledAuthInfos
	for _, kubeContext := range config.Contexts {
		if profiledName, found := renamed[kubeContext.AuthInfo]; found {
			kubeContext.AuthInfo = profiledName
		}
	}
}

func resolveServerURL() (string, error) {
	if serverURL != "" {
		return validateServerURL(serverURL)
	}

	if domain, err := detectDomain(); err == nil {
		for d := domain; strings.Contains(d, "."); {
			if servers := discoverDNS(d); len(servers) > 0 {
				selected, err := selectServer(servers)
				if err != nil {
					return "", err
				}
				return validateServerURL(selected)
			}
			_, d, _ = strings.Cut(d, ".")
		}
	}

	if cached, err := token.NewStorage(token.DefaultCachePath()).Load(); err == nil && cached != nil && cached.ServerURL != "" {
		return validateServerURL(cached.ServerURL)
	}

	return "", fmt.Errorf("no kauth servers found.\n\nConfigure DNS TXT records at _kauth.<domain> or run:\n  kauth login --url <server-url>")
}

func validateServerURL(rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("kauth server URL must be an HTTPS origin")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	return parsed.String(), nil
}

func validateHTTPSURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return fmt.Errorf("URL must use HTTPS")
	}
	return nil
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
func watchForCompletion(ctx context.Context, client *http.Client, baseURL, sessionToken string) (*StatusResponse, error) {
	for {
		status, retriable, err := watchOnce(ctx, client, baseURL, sessionToken)
		switch {
		case err != nil && !retriable:
			return nil, err
		case status != nil:
			return status, nil
		}

		if debug {
			fmt.Fprintf(os.Stderr, "  [debug] reconnecting in 2s...\n")
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("timed out waiting for authentication.\n\nPlease try logging in again")
		case <-time.After(2 * time.Second):
		}
	}
}

// watchOnce makes a single /watch connection. It returns a non-nil status on
// success. retriable is true when the connection dropped or idled without a
// result, signalling the caller to reconnect.
func watchOnce(ctx context.Context, client *http.Client, baseURL, sessionToken string) (status *StatusResponse, retriable bool, err error) {
	watchURL := fmt.Sprintf("%s/watch?session_token=%s", baseURL, url.QueryEscape(sessionToken))
	resp, err := getWithContext(ctx, client, watchURL)
	if err != nil {
		if ctx.Err() != nil {
			return nil, false, fmt.Errorf("timed out waiting for authentication.\n\nPlease try logging in again")
		}
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

func getWithContext(ctx context.Context, client *http.Client, requestURL string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, err
	}
	return client.Do(req)
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

func hasConflict(data []byte, incoming *clientcmdapi.Config) bool {
	existing, err := clientcmd.Load(data)
	if err != nil {
		return false
	}
	for name := range incoming.Contexts {
		if _, found := existing.Contexts[name]; found {
			return true
		}
	}
	for name := range incoming.Clusters {
		if _, found := existing.Clusters[name]; found {
			return true
		}
	}
	for name := range incoming.AuthInfos {
		if _, found := existing.AuthInfos[name]; found {
			return true
		}
	}
	return false
}

var httpClient = &http.Client{
	Timeout: 30 * time.Second,
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
	RequestID    string `json:"request_id,omitempty"`
}

type RefreshResponse struct {
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	TokenType    string `json:"token_type"`
	Kubeconfig   string `json:"kubeconfig"`
}

func refreshTokenFromServer(baseURL, refreshToken, requestID string) (*RefreshResponse, error) {
	reqBody, err := json.Marshal(RefreshRequest{RefreshToken: refreshToken, RequestID: requestID})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := httpClient.Post(
		baseURL+"/refresh",
		"application/json",
		strings.NewReader(string(reqBody)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to server: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	var refreshResp RefreshResponse
	if err := json.NewDecoder(resp.Body).Decode(&refreshResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &refreshResp, nil
}

func ensureFreshIDToken(storage *token.Storage, cached *token.Cache) error {
	expectedServerURL := cached.ServerURL
	expectedSessionID := cached.SessionID
	return storage.WithLock(35*time.Second, func() error {
		latest, err := storage.Load()
		if err != nil {
			return err
		}
		if latest == nil {
			return fmt.Errorf("token cache disappeared")
		}
		if latest.ServerURL != expectedServerURL || latest.SessionID != expectedSessionID {
			return fmt.Errorf("credentials changed while waiting for the token cache lock")
		}
		*cached = *latest
		for range 2 {
			claims := decodeJWTClaims(cached.IDToken)
			if cached.IDToken != "" {
				if exp, ok := claims["exp"].(float64); ok && time.Unix(int64(exp), 0).After(time.Now().Add(time.Minute)) {
					return nil
				}
			}
			if cached.RefreshToken == "" {
				return fmt.Errorf("no refresh token available")
			}
			if cached.RefreshRequestID == "" {
				cached.RefreshRequestID = rand.Text()
				if err := storage.Save(cached); err != nil {
					return err
				}
			}
			refreshed, err := refreshTokenFromServer(cached.ServerURL, cached.RefreshToken, cached.RefreshRequestID)
			if err != nil {
				return err
			}
			if refreshed.IDToken == "" || refreshed.RefreshToken == "" {
				return fmt.Errorf("server returned incomplete refresh response")
			}
			cached.IDToken = refreshed.IDToken
			cached.RefreshToken = refreshed.RefreshToken
			cached.RefreshRequestID = ""
			if err := storage.Save(cached); err != nil {
				return err
			}
			claims = decodeJWTClaims(cached.IDToken)
			exp, ok := claims["exp"].(float64)
			if !ok {
				return fmt.Errorf("server returned an invalid ID token")
			}
			if time.Unix(int64(exp), 0).After(time.Now().Add(time.Minute)) {
				return nil
			}
		}
		return fmt.Errorf("server replayed an expired management token")
	})
}

func validateRemoteKubeconfig(config *clientcmdapi.Config) error {
	if config.APIVersion != "v1" || config.Kind != "Config" || len(config.Clusters) != 1 ||
		len(config.AuthInfos) != 1 || len(config.Contexts) != 1 || len(config.Extensions) != 0 ||
		config.Preferences.Colors || len(config.Preferences.Extensions) != 0 {
		return fmt.Errorf("unexpected kubeconfig structure from server")
	}
	kubeContext := config.Contexts[config.CurrentContext]
	if kubeContext == nil {
		return fmt.Errorf("kubeconfig current context is missing")
	}
	cluster := config.Clusters[kubeContext.Cluster]
	authInfo := config.AuthInfos[kubeContext.AuthInfo]
	if cluster == nil || authInfo == nil {
		return fmt.Errorf("kubeconfig current context has missing references")
	}
	serverURL, err := url.Parse(cluster.Server)
	if err != nil || serverURL.Scheme != "https" || serverURL.Host == "" || len(cluster.CertificateAuthorityData) == 0 {
		return fmt.Errorf("unsafe cluster endpoint in kubeconfig")
	}
	expectedCluster := &clientcmdapi.Cluster{
		Server:                   cluster.Server,
		CertificateAuthorityData: cluster.CertificateAuthorityData,
	}
	if !reflect.DeepEqual(cluster, expectedCluster) {
		return fmt.Errorf("unexpected cluster configuration in kubeconfig")
	}
	expectedContext := &clientcmdapi.Context{
		Cluster:   kubeContext.Cluster,
		AuthInfo:  kubeContext.AuthInfo,
		Namespace: "default",
	}
	if !reflect.DeepEqual(kubeContext, expectedContext) {
		return fmt.Errorf("unexpected context configuration in kubeconfig")
	}
	expectedAuthInfo := &clientcmdapi.AuthInfo{Exec: &clientcmdapi.ExecConfig{
		APIVersion:      "client.authentication.k8s.io/v1",
		Command:         "kauth",
		Args:            []string{"get-token"},
		InteractiveMode: clientcmdapi.NeverExecInteractiveMode,
	}}
	for name, authInfo := range config.AuthInfos {
		if !reflect.DeepEqual(authInfo, expectedAuthInfo) {
			return fmt.Errorf("unsafe exec configuration for user %q", name)
		}
	}
	return nil
}

func mergeKubeconfig(existingPath string, incoming *clientcmdapi.Config) error {
	existing, err := clientcmd.LoadFromFile(existingPath)
	if err != nil {
		return fmt.Errorf("failed to parse existing kubeconfig: %w", err)
	}
	for name, cluster := range incoming.Clusters {
		existing.Clusters[name] = cluster
	}
	for name, authInfo := range incoming.AuthInfos {
		existing.AuthInfos[name] = authInfo
	}
	for name, kubeContext := range incoming.Contexts {
		existing.Contexts[name] = kubeContext
	}
	if incoming.CurrentContext != "" {
		existing.CurrentContext = incoming.CurrentContext
	}
	return writeKubeconfigAtomic(existingPath, existing)
}

func writeKubeconfigAtomic(path string, config *clientcmdapi.Config) error {
	for range 8 {
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) || err == nil && info.Mode()&os.ModeSymlink == 0 {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to inspect kubeconfig path: %w", err)
		}
		target, err := os.Readlink(path)
		if err != nil {
			return fmt.Errorf("failed to read kubeconfig symlink: %w", err)
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(path), target)
		}
		path = filepath.Clean(target)
	}
	data, err := clientcmd.Write(*config)
	if err != nil {
		return fmt.Errorf("failed to marshal kubeconfig: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".kauth-kubeconfig-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	return nil
}
