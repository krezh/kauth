//go:build e2e

package e2e

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"kauth/pkg/audit"
	"kauth/pkg/session"
	"kauth/pkg/token"

	"github.com/jackc/pgx/v5/pgxpool"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

const (
	kauthNamespace = "kauth"
	testNamespace  = "kauth-e2e"
	testGroup      = "kauth-e2e-allowed"
	testUser       = "e2e-user@example.com"
	// e2eClusterName must match the CLUSTER_NAME set in deployKauth's Helm values.
	e2eClusterName = "e2e"
)

var environment *e2eEnvironment

type e2eEnvironment struct {
	repoRoot         string
	tempDir          string
	clusterName      string
	clusterConfig    string
	image            string
	proxyURL         string
	proxyCA          []byte
	proxyServer      *httptest.Server
	loginBrowser     *http.Client
	backendPort      int
	kauthBinary      string
	serverBinary     string
	oidcBinary       string
	portForward      *exec.Cmd
	portForwardLog   *os.File
	dbPort           int
	dbPortForward    *exec.Cmd
	dbPortForwardLog *bytes.Buffer
	sessionClient    *session.Client
	clientset        *kubernetes.Clientset
	kubectlConfig    string
	sessionID        string
	apiToken         string
	refreshToken     string
}

func TestMain(m *testing.M) {
	env, err := setupEnvironment()
	if err != nil {
		fmt.Fprintf(os.Stderr, "E2E setup failed: %v\n", err)
		os.Exit(1)
	}
	environment = env

	code := m.Run()
	if err := env.cleanup(); err != nil {
		fmt.Fprintf(os.Stderr, "E2E cleanup failed: %v\n", err)
		if code == 0 {
			code = 1
		}
	}
	os.Exit(code)
}

func setupEnvironment() (*e2eEnvironment, error) {
	for _, command := range []string{"docker", "helm", "kind", "kubectl"} {
		if _, err := exec.LookPath(command); err != nil {
			return nil, fmt.Errorf("required command %q not found: %w", command, err)
		}
	}

	_, currentFile, _, _ := runtime.Caller(0)
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
	tempDir, err := os.MkdirTemp("", "kauth-e2e-")
	if err != nil {
		return nil, err
	}

	clusterName := fmt.Sprintf("kauth-e2e-%d", os.Getpid())
	env := &e2eEnvironment{
		repoRoot:      repoRoot,
		tempDir:       tempDir,
		clusterName:   clusterName,
		clusterConfig: filepath.Join(tempDir, "kind.kubeconfig"),
		image:         "kauth-e2e:" + clusterName,
		kauthBinary:   filepath.Join(tempDir, "kauth"),
		serverBinary:  filepath.Join(tempDir, "kauth-server"),
		oidcBinary:    filepath.Join(tempDir, "oidc-provider"),
	}

	if err := env.buildBinaries(); err != nil {
		_ = env.cleanup()
		return nil, err
	}
	if _, err := env.run("kind", "create", "cluster", "--name", env.clusterName, "--kubeconfig", env.clusterConfig, "--wait", "120s"); err != nil {
		_ = env.cleanup()
		return nil, err
	}
	if err := env.buildAndLoadImage(); err != nil {
		_ = env.cleanup()
		return nil, err
	}
	if err := env.deployKauth(); err != nil {
		_ = env.cleanup()
		return nil, err
	}
	if err := env.startPortForward(); err != nil {
		_ = env.cleanup()
		return nil, err
	}
	if err := env.configureCluster(); err != nil {
		_ = env.cleanup()
		return nil, err
	}
	return env, nil
}

func (e *e2eEnvironment) buildBinaries() error {
	for output, pkg := range map[string]string{
		e.kauthBinary:  "./cmd/kauth",
		e.serverBinary: "./cmd/kauth-server",
		e.oidcBinary:   "./test/e2e/oidc",
	} {
		cmd := exec.Command("go", "build", "-tags=e2e", "-o", output, pkg)
		cmd.Dir = e.repoRoot
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("build %s: %w\n%s", pkg, err, output)
		}
	}
	return nil
}

func (e *e2eEnvironment) buildAndLoadImage() error {
	dockerfile := filepath.Join(e.tempDir, "Dockerfile")
	if err := os.WriteFile(dockerfile, []byte("FROM scratch\nCOPY kauth-server /kauth-server\nCOPY oidc-provider /oidc-provider\nUSER 1000\nENTRYPOINT [\"/kauth-server\"]\n"), 0600); err != nil {
		return err
	}
	if _, err := e.run("docker", "build", "--tag", e.image, e.tempDir); err != nil {
		return err
	}
	_, err := e.run("kind", "load", "docker-image", e.image, "--name", e.clusterName)
	return err
}

func (e *e2eEnvironment) deployKauth() error {
	backendPort, err := availablePort()
	if err != nil {
		return err
	}
	e.backendPort = backendPort
	backendURL, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", backendPort))
	if err != nil {
		return err
	}
	proxy := &httputil.ReverseProxy{
		ErrorLog: log.New(io.Discard, "", 0),
		Rewrite: func(request *httputil.ProxyRequest) {
			request.SetURL(backendURL)
		},
	}
	e.proxyServer = httptest.NewTLSServer(proxy)
	e.proxyURL = e.proxyServer.URL
	e.proxyCA = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.proxyServer.Certificate().Raw})

	if err := e.deployOIDCProvider(); err != nil {
		return err
	}

	signingKey := bytes.Repeat([]byte{0x11}, 32)
	encryptionKey := bytes.Repeat([]byte{0x22}, 32)

	values := fmt.Sprintf(`replicaCount: 2
image:
  repository: kauth-e2e
  tag: %s
  pullPolicy: Never
podDisruptionBudget:
  enabled: false
env:
  - name: OIDC_ISSUER_URL
    value: http://oidc.kauth.svc.cluster.local:8080
  - name: OIDC_CLIENT_ID
    value: e2e
  - name: OIDC_CLIENT_SECRET
    value: e2e
  - name: JWT_SIGNING_KEY
    value: %s
  - name: JWT_ENCRYPTION_KEY
    value: %s
  - name: BASE_URL
    value: %s
  - name: CLUSTER_NAME
    value: %s
  - name: DATABASE_URL
    value: postgres://kauth:kauth@postgres.kauth.svc.cluster.local:5432/kauth?sslmode=disable
  - name: ADMIN_GROUPS
    value: kauth-e2e-allowed
  - name: AUDIT_QUEUE_SIZE
    value: "8"
`, e.clusterName, base64.StdEncoding.EncodeToString(signingKey), base64.StdEncoding.EncodeToString(encryptionKey), e.proxyURL, e2eClusterName)
	valuesPath := filepath.Join(e.tempDir, "values.yaml")
	if err := os.WriteFile(valuesPath, []byte(values), 0600); err != nil {
		return err
	}

	_, err = e.run(
		"helm", "upgrade", "--install", "kauth", filepath.Join(e.repoRoot, "helm"),
		"--kubeconfig", e.clusterConfig,
		"--namespace", "kauth", "--create-namespace",
		"--values", valuesPath,
		"--wait", "--timeout", "120s",
	)
	return err
}

func (e *e2eEnvironment) deployOIDCProvider() error {
	manifest := fmt.Sprintf(`apiVersion: v1
kind: Namespace
metadata:
  name: kauth
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: postgres
  namespace: kauth
spec:
  serviceName: postgres
  replicas: 1
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      containers:
        - name: postgres
          image: postgres:18-alpine
          env:
            - name: POSTGRES_USER
              value: kauth
            - name: POSTGRES_PASSWORD
              value: kauth
            - name: POSTGRES_DB
              value: kauth
          readinessProbe:
            exec:
              command: ["pg_isready", "-U", "kauth"]
          volumeMounts:
            - name: data
              mountPath: /var/lib/postgresql
  volumeClaimTemplates:
    - metadata:
        name: data
      spec:
        accessModes: ["ReadWriteOnce"]
        resources:
          requests:
            storage: 1Gi
---
apiVersion: v1
kind: Service
metadata:
  name: postgres
  namespace: kauth
spec:
  selector:
    app: postgres
  ports:
    - port: 5432
      targetPort: 5432
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: oidc
  namespace: kauth
spec:
  replicas: 1
  selector:
    matchLabels:
      app: oidc
  template:
    metadata:
      labels:
        app: oidc
    spec:
      containers:
        - name: oidc
          image: %s
          imagePullPolicy: Never
          command: ["/oidc-provider"]
          env:
            - name: ISSUER_URL
              value: http://oidc.kauth.svc.cluster.local:8080
          readinessProbe:
            httpGet:
              path: /health
              port: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: oidc
  namespace: kauth
spec:
  selector:
    app: oidc
  ports:
    - port: 8080
      targetPort: 8080
`, e.image)
	manifestPath := filepath.Join(e.tempDir, "oidc.yaml")
	if err := os.WriteFile(manifestPath, []byte(manifest), 0600); err != nil {
		return err
	}
	if _, err := e.run("kubectl", "--kubeconfig", e.clusterConfig, "apply", "-f", manifestPath); err != nil {
		return err
	}
	if _, err := e.run("kubectl", "--kubeconfig", e.clusterConfig, "--namespace", kauthNamespace, "rollout", "status", "statefulset/postgres", "--timeout=120s"); err != nil {
		return err
	}
	_, err := e.run("kubectl", "--kubeconfig", e.clusterConfig, "--namespace", kauthNamespace, "rollout", "status", "deployment/oidc", "--timeout=120s")
	return err
}

func (e *e2eEnvironment) startPortForward() error {
	logPath := filepath.Join(e.tempDir, "port-forward.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		return err
	}
	e.portForwardLog = logFile
	e.portForward = exec.Command("kubectl", "--kubeconfig", e.clusterConfig, "--namespace", "kauth", "port-forward", "service/kauth-server", fmt.Sprintf("%d:8080", e.backendPort))
	e.portForward.Stdout = logFile
	e.portForward.Stderr = logFile
	if err := e.portForward.Start(); err != nil {
		_ = logFile.Close()
		return err
	}

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		response, requestErr := e.proxyServer.Client().Get(e.proxyURL + "/api/health")
		if requestErr == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	content, _ := os.ReadFile(logPath)
	return fmt.Errorf("port-forward did not become ready:\n%s", content)
}

func (e *e2eEnvironment) stopPortForward() {
	if e.portForward != nil && e.portForward.Process != nil {
		_ = e.portForward.Process.Kill()
		_, _ = e.portForward.Process.Wait()
	}
	e.portForward = nil
	if e.portForwardLog != nil {
		_ = e.portForwardLog.Close()
	}
	e.portForwardLog = nil
}

func (e *e2eEnvironment) sessionDatabaseURL() string {
	return fmt.Sprintf("postgres://kauth:kauth@127.0.0.1:%d/kauth?sslmode=disable", e.dbPort)
}

func (e *e2eEnvironment) startDBPortForward() error {
	port, cmd, output, err := e.clusterPortForward(kauthNamespace, "service/postgres", 5432)
	if err != nil {
		return err
	}
	e.dbPort = port
	e.dbPortForward = cmd
	e.dbPortForwardLog = output

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		testPool, poolErr := pgxpool.New(context.Background(), e.sessionDatabaseURL())
		if poolErr == nil {
			pingErr := testPool.Ping(context.Background())
			testPool.Close()
			if pingErr == nil {
				return nil
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("db port-forward did not become ready:\n%s", output.String())
}

func (e *e2eEnvironment) stopDBPortForward() {
	if e.dbPortForward != nil && e.dbPortForward.Process != nil {
		_ = e.dbPortForward.Process.Kill()
		_, _ = e.dbPortForward.Process.Wait()
	}
	e.dbPortForward = nil
}

// restartSessionClient rebuilds the DB port-forward and sessionClient after a Postgres pod identity change.
func (e *e2eEnvironment) restartSessionClient(t *testing.T) {
	t.Helper()
	if e.sessionClient != nil {
		_ = e.sessionClient.Close(context.Background())
	}
	e.stopDBPortForward()
	if err := e.startDBPortForward(); err != nil {
		t.Fatalf("restart DB port-forward: %v", err)
	}
	sessionCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sessionClient, err := session.NewClient(sessionCtx, e.sessionDatabaseURL(), e2eClusterName)
	if err != nil {
		t.Fatalf("rebuild session client: %v", err)
	}
	e.sessionClient = sessionClient
}

func (e *e2eEnvironment) configureCluster() error {
	config, err := clientcmd.BuildConfigFromFlags("", e.clusterConfig)
	if err != nil {
		return err
	}
	e.clientset, err = kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}
	if err := e.startDBPortForward(); err != nil {
		return err
	}
	sessionCtx, sessionCancel := context.WithTimeout(context.Background(), 30*time.Second)
	e.sessionClient, err = session.NewClient(sessionCtx, e.sessionDatabaseURL(), e2eClusterName)
	sessionCancel()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	if _, err := e.clientset.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testNamespace}}, metav1.CreateOptions{}); err != nil {
		return err
	}
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: "kauth-e2e", Namespace: testNamespace},
		Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"configmaps", "pods", "pods/log"}, Verbs: []string{"get", "list", "watch", "create", "update", "patch", "delete"}},
			{APIGroups: []string{""}, Resources: []string{"pods/exec", "pods/attach", "pods/portforward"}, Verbs: []string{"get", "create"}},
		},
	}
	if _, err := e.clientset.RbacV1().Roles(testNamespace).Create(ctx, role, metav1.CreateOptions{}); err != nil {
		return err
	}
	binding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "kauth-e2e", Namespace: testNamespace},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: role.Name},
		Subjects:   []rbacv1.Subject{{Kind: rbacv1.GroupKind, Name: testGroup}},
	}
	if _, err := e.clientset.RbacV1().RoleBindings(testNamespace).Create(ctx, binding, metav1.CreateOptions{}); err != nil {
		return err
	}
	workload := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "streaming-workload", Namespace: testNamespace},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "server", Image: "busybox:1.37",
				Command: []string{"sh", "-c", "mkdir -p /www; echo kauth-port-forward-ok >/www/index.html; echo kauth-log-ok; exec httpd -f -p 8080 -h /www"},
				Ports:   []corev1.ContainerPort{{ContainerPort: 8080}},
			}},
			RestartPolicy: corev1.RestartPolicyNever,
		},
	}
	if _, err := e.clientset.CoreV1().Pods(testNamespace).Create(ctx, workload, metav1.CreateOptions{}); err != nil {
		return err
	}
	if err := e.waitForPodReady(ctx, testNamespace, workload.Name); err != nil {
		return err
	}

	kubeconfig, err := e.login()
	if err != nil {
		return err
	}
	if _, err := e.sessionClient.Create(ctx, "other-user-session", "other-verifier", "other@example.com"); err != nil {
		return err
	}
	if err := e.sessionClient.UpdateStatus(ctx, "other-user-session", session.Status{
		Phase: session.PhaseActive, Email: "other@example.com", Username: "other-user", Groups: []string{"users"},
	}); err != nil {
		return err
	}
	e.kubectlConfig, err = e.writeKubectlConfig(kubeconfig)
	return err
}

func (e *e2eEnvironment) waitForPodReady(ctx context.Context, namespace, name string) error {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		pod, err := e.clientset.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
		if err == nil {
			for _, condition := range pod.Status.Conditions {
				if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
					return nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("pod %s/%s did not become ready: %w", namespace, name, ctx.Err())
		case <-ticker.C:
		}
	}
}

type startLoginResponse struct {
	SessionToken string `json:"session_token"`
	LoginURL     string `json:"login_url"`
}

type loginStatus struct {
	Ready        bool   `json:"ready"`
	Kubeconfig   string `json:"kubeconfig"`
	APIToken     string `json:"api_token"`
	SessionID    string `json:"session_id"`
	RefreshToken string `json:"refresh_token"`
	Error        string `json:"error"`
}

func (e *e2eEnvironment) login() (string, error) {
	client := e.proxyServer.Client()
	var started startLoginResponse
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		response, err := client.Get(e.proxyURL + "/api/start-login")
		if err == nil {
			if response.StatusCode == http.StatusOK {
				err = json.NewDecoder(response.Body).Decode(&started)
				_ = response.Body.Close()
				if err != nil {
					return "", err
				}
				break
			}
			_ = response.Body.Close()
		}
		time.Sleep(250 * time.Millisecond)
	}
	if started.SessionToken == "" {
		return "", fmt.Errorf("OIDC provider did not become ready")
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return "", err
	}
	browser := e.dashboardHTTPClient(jar)
	loginURL, err := url.Parse(started.LoginURL)
	if err != nil {
		return "", err
	}
	if loginURL.Query().Get("session_token") != "" {
		return "", fmt.Errorf("CLI credential leaked into login URL")
	}
	e.sessionID = loginURL.Query().Get("state")
	if e.sessionID == "" {
		return "", fmt.Errorf("login URL has no state: %s", started.LoginURL)
	}

	challenge := loginURL.Query().Get("code_challenge")
	if challenge == "" || loginURL.Query().Get("code_challenge_method") != "S256" {
		return "", fmt.Errorf("login URL has no PKCE challenge: %s", started.LoginURL)
	}
	callbackURL := fmt.Sprintf("%s/callback?state=%s&code=%s", e.proxyURL, url.QueryEscape(e.sessionID), url.QueryEscape("e2e-code."+challenge))
	response, err := browser.Get(callbackURL)
	if err != nil {
		return "", err
	}
	callbackBody, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusSeeOther || response.Header.Get("Location") != "/" {
		return "", fmt.Errorf("callback returned %d: %s", response.StatusCode, callbackBody)
	}
	e.loginBrowser = browser

	watchURL := fmt.Sprintf("%s/api/watch?session_token=%s", e.proxyURL, url.QueryEscape(started.SessionToken))
	response, err = client.Get(watchURL)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	scanner := bufio.NewScanner(response.Body)
	for scanner.Scan() {
		data, ok := strings.CutPrefix(scanner.Text(), "data: ")
		if !ok {
			continue
		}
		var status loginStatus
		if err := json.Unmarshal([]byte(data), &status); err != nil {
			return "", err
		}
		if status.Error != "" {
			return "", fmt.Errorf("login failed: %s", status.Error)
		}
		if status.Ready {
			e.apiToken = status.APIToken
			e.refreshToken = status.RefreshToken
			if status.SessionID != "" {
				e.sessionID = status.SessionID
			}
			if e.apiToken == "" || e.refreshToken == "" || status.Kubeconfig == "" {
				return "", fmt.Errorf("login result omitted API token, refresh token, or kubeconfig")
			}
			return status.Kubeconfig, nil
		}
	}
	return "", fmt.Errorf("watch ended without login result: %w", scanner.Err())
}

func (e *e2eEnvironment) writeKubectlConfig(generated string) (string, error) {
	home := filepath.Join(e.tempDir, "home")
	cachePath := filepath.Join(home, ".kube", "cache", "kauth-token.json")
	if err := token.NewStorage(cachePath).Save(&token.Cache{
		ServerURL: e.proxyURL,
		SessionID: e.sessionID,
		APIToken:  e.apiToken,
		Expiry:    time.Now().Add(time.Hour),
	}); err != nil {
		return "", err
	}

	config, err := clientcmd.Load([]byte(generated))
	if err != nil {
		return "", err
	}
	for _, cluster := range config.Clusters {
		if cluster.Server != e.proxyURL+"/k8s" {
			return "", fmt.Errorf("generated kubeconfig server = %q, want %q", cluster.Server, e.proxyURL+"/k8s")
		}
	}
	for _, cluster := range config.Clusters {
		cluster.CertificateAuthorityData = e.proxyCA
	}
	for _, authInfo := range config.AuthInfos {
		if authInfo.Exec == nil {
			return "", fmt.Errorf("generated kubeconfig has no exec credential")
		}
		authInfo.Exec.Command = e.kauthBinary
		authInfo.Exec.Env = []clientcmdapi.ExecEnvVar{{Name: "HOME", Value: home}}
	}
	for _, contextConfig := range config.Contexts {
		contextConfig.Namespace = testNamespace
	}
	path := filepath.Join(e.tempDir, "kubectl.kubeconfig")
	return path, clientcmd.WriteToFile(*config, path)
}

func TestKauthProxyEndToEnd(t *testing.T) {
	t.Run("CLI callback does not establish an unbound dashboard session", func(t *testing.T) {
		response, err := environment.loginBrowser.Get(environment.proxyURL + "/")
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		if response.StatusCode != http.StatusOK || !strings.Contains(string(body), "Sign in") || strings.Contains(string(body), testUser) {
			t.Fatalf("dashboard after CLI login = %d: %s", response.StatusCode, body)
		}
	})

	t.Run("kubectl exec credential and discovery", func(t *testing.T) {
		output := environment.kubectl(t, "get", "--raw", "/version")
		if !strings.Contains(output, `"gitVersion"`) {
			t.Fatalf("unexpected version response: %s", output)
		}
	})

	t.Run("missing and malformed credentials are rejected", func(t *testing.T) {
		for name, authorization := range map[string]string{"missing": "", "malformed": "Bearer not-a-kauth-token"} {
			t.Run(name, func(t *testing.T) {
				request, err := http.NewRequest(http.MethodGet, environment.proxyURL+"/k8s/version", nil)
				if err != nil {
					t.Fatal(err)
				}
				if authorization != "" {
					request.Header.Set("Authorization", authorization)
				}
				response, err := environment.proxyServer.Client().Do(request)
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				if response.StatusCode != http.StatusUnauthorized || response.Header.Get("WWW-Authenticate") != "Bearer" {
					t.Fatalf("response=%d authenticate=%q", response.StatusCode, response.Header.Get("WWW-Authenticate"))
				}
			})
		}
	})

	t.Run("refresh rotation and replay rejection", func(t *testing.T) {
		original := environment.refreshToken
		type refreshResult struct {
			token  string
			status int
			body   string
			err    error
		}
		results := make(chan refreshResult, 2)
		for range 2 {
			go func() {
				token, status, body, err := environment.refreshRequest(original)
				results <- refreshResult{token: token, status: status, body: body, err: err}
			}()
		}
		var rotated string
		statuses := map[int]int{}
		for range 2 {
			result := <-results
			if result.err != nil {
				t.Fatal(result.err)
			}
			statuses[result.status]++
			if result.status == http.StatusOK {
				rotated = result.token
			}
		}
		if statuses[http.StatusOK] != 1 || statuses[http.StatusUnauthorized] != 1 || rotated == "" || rotated == original {
			t.Fatalf("concurrent refresh statuses=%v token_changed=%v", statuses, rotated != original)
		}
		_, replayStatus, replayBody := environment.refresh(t, original)
		if replayStatus != http.StatusUnauthorized {
			t.Fatalf("replayed refresh status=%d, want 401: %s", replayStatus, replayBody)
		}
		environment.refreshToken = rotated
	})

	t.Run("namespaced RBAC and CRUD", func(t *testing.T) {
		environment.kubectl(t, "create", "configmap", "created-through-kauth", "--from-literal=value=ok")
		output := environment.kubectl(t, "get", "configmap", "created-through-kauth", "--output", "jsonpath={.data.value}")
		if output != "ok" {
			t.Fatalf("configmap value = %q", output)
		}
	})

	t.Run("exec logs and port-forward upgrades", func(t *testing.T) {
		output := environment.kubectl(t, "exec", "streaming-workload", "--", "sh", "-c", "printf kauth-exec-ok")
		if output != "kauth-exec-ok" {
			t.Fatalf("exec output = %q", output)
		}
		if output := environment.kubectl(t, "logs", "streaming-workload"); !strings.Contains(output, "kauth-log-ok") {
			t.Fatalf("logs output = %q", output)
		}
		port, err := availablePort()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "kubectl", "--kubeconfig", environment.kubectlConfig, "port-forward", "pod/streaming-workload", fmt.Sprintf("%d:8080", port))
		var commandOutput bytes.Buffer
		cmd.Stdout = &commandOutput
		cmd.Stderr = &commandOutput
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
		deadline := time.Now().Add(10 * time.Second)
		for {
			response, requestErr := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", port))
			if requestErr == nil {
				body, _ := io.ReadAll(response.Body)
				_ = response.Body.Close()
				if response.StatusCode == http.StatusOK && strings.TrimSpace(string(body)) == "kauth-port-forward-ok" {
					break
				}
			}
			if time.Now().After(deadline) {
				t.Fatalf("port-forward failed: %s", commandOutput.String())
			}
			time.Sleep(200 * time.Millisecond)
		}
	})

	t.Run("reserved groups and spoofed identity are denied", func(t *testing.T) {
		request, err := http.NewRequest(http.MethodGet, environment.proxyURL+"/k8s/api/v1/nodes", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+environment.apiToken)
		request.Header.Set("Impersonate-User", "system:admin")
		request.Header.Set("Impersonate-Group", "system:masters")
		response, err := environment.proxyServer.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		if response.StatusCode != http.StatusForbidden {
			t.Fatalf("GET nodes status = %d, want 403: %s", response.StatusCode, body)
		}
	})

	t.Run("watch streaming", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "kubectl", "--kubeconfig", environment.kubectlConfig, "get", "configmaps", "--watch-only", "--output=name")
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Second)
		environment.kubectl(t, "create", "configmap", "watched-through-kauth", "--from-literal=value=ok")

		lines := make(chan string, 1)
		go func() {
			scanner := bufio.NewScanner(stdout)
			for scanner.Scan() {
				if strings.Contains(scanner.Text(), "watched-through-kauth") {
					lines <- scanner.Text()
					return
				}
			}
			lines <- ""
		}()
		select {
		case line := <-lines:
			if line == "" {
				t.Fatalf("watch ended without event: %s", stderr.String())
			}
		case <-ctx.Done():
			t.Fatalf("watch timed out: %s", stderr.String())
		}
		cancel()
		_ = cmd.Wait()
	})

	t.Run("concurrent proxy traffic", func(t *testing.T) {
		const requests = 64
		errors := make(chan error, requests)
		var wait sync.WaitGroup
		for range requests {
			wait.Add(1)
			go func() {
				defer wait.Done()
				request, err := http.NewRequest(http.MethodGet, environment.proxyURL+"/k8s/version", nil)
				if err != nil {
					errors <- err
					return
				}
				request.Header.Set("Authorization", "Bearer "+environment.apiToken)
				response, err := environment.proxyServer.Client().Do(request)
				if err != nil {
					errors <- err
					return
				}
				_ = response.Body.Close()
				if response.StatusCode != http.StatusOK {
					errors <- fmt.Errorf("status %d", response.StatusCode)
				}
			}()
		}
		wait.Wait()
		close(errors)
		for err := range errors {
			t.Errorf("concurrent request failed: %v", err)
		}
	})

	t.Run("every replica shares sessions", func(t *testing.T) {
		pods, err := environment.clientset.CoreV1().Pods(kauthNamespace).List(context.Background(), metav1.ListOptions{LabelSelector: "app.kubernetes.io/name=kauth-server"})
		if err != nil {
			t.Fatal(err)
		}
		if len(pods.Items) != 2 {
			t.Fatalf("kauth replicas = %d, want 2", len(pods.Items))
		}
		for _, pod := range pods.Items {
			if err := environment.requestThroughPod(pod.Name); err != nil {
				t.Errorf("pod %s: %v", pod.Name, err)
			}
		}
	})

	t.Run("structured session audit", func(t *testing.T) {
		output := environment.clusterKubectl(t, "--namespace", "kauth", "logs", "-l", "app.kubernetes.io/name=kauth-server", "--prefix=true", "--tail=-1")
		for _, expected := range []string{
			`"audit_event":"kubernetes_request"`,
			`"session_id":"` + environment.sessionID + `"`,
			`"user":"` + testUser + `"`,
			`"path":"/api/v1/namespaces/kauth-e2e/configmaps"`,
		} {
			if !strings.Contains(output, expected) {
				t.Fatalf("audit output missing %s:\n%s", expected, output)
			}
		}
	})

	t.Run("dashboard login, metrics, and request history", func(t *testing.T) {
		client := environment.dashboardClient(t, "dashboard-user-code")

		deadline := time.Now().Add(10 * time.Second)
		for {
			response, err := client.Get(environment.proxyURL + "/sessions/" + url.PathEscape(environment.sessionID))
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(response.Body)
			_ = response.Body.Close()
			page := string(body)
			if response.StatusCode == http.StatusOK && strings.Contains(page, "Kubernetes access telemetry") && strings.Contains(page, "/api/v1/namespaces/kauth-e2e/configmaps") {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("dashboard did not show persisted request history: status=%d body=%s", response.StatusCode, page)
			}
			time.Sleep(250 * time.Millisecond)
		}
		response, err := client.Get(environment.proxyURL + "/sessions/other-user-session")
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusForbidden {
			t.Fatalf("non-admin cross-user detail status = %d, want 403", response.StatusCode)
		}

		adminClient := environment.dashboardClient(t, "dashboard-admin-code")
		response, err = adminClient.Get(environment.proxyURL + "/sessions/other-user-session")
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("admin cross-user detail status = %d, want 200", response.StatusCode)
		}
	})

	t.Run("dashboard state CSRF and pagination defenses", func(t *testing.T) {
		before, err := environment.sessionClient.ListAll(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		anonymousClient := environment.dashboardHTTPClient(nil)
		response, err := anonymousClient.Get(environment.proxyURL + "/")
		if err != nil {
			t.Fatal(err)
		}
		page, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK || !strings.Contains(string(page), "Sign in") {
			t.Fatalf("anonymous dashboard = %d: %s", response.StatusCode, page)
		}
		after, err := environment.sessionClient.ListAll(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(after) != len(before) {
			t.Fatalf("anonymous dashboard created a session: before=%d after=%d", len(before), len(after))
		}

		client, dashboardState, dashboardChallenge := environment.dashboardLoginStart(t)
		afterLoginStart, err := environment.sessionClient.ListAll(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(afterLoginStart) != len(after) {
			t.Fatalf("dashboard login created a session: before=%d after=%d", len(after), len(afterLoginStart))
		}
		response, err = client.Get(environment.proxyURL + "/callback?state=wrong&code=dashboard-user-code")
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("invalid dashboard state status=%d, want 400", response.StatusCode)
		}
		callbackURL, _ := url.Parse(environment.proxyURL + "/callback")
		if cookies := client.Jar.Cookies(callbackURL); !hasCookie(cookies, "__Host-kauth_dashboard_login") {
			t.Fatalf("mismatched callback removed dashboard login cookie: %#v", cookies)
		}
		validCallback := environment.proxyURL + "/callback?state=" + url.QueryEscape(dashboardState) + "&code=" + url.QueryEscape("dashboard-user-code."+dashboardChallenge)
		response, err = client.Get(validCallback)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusSeeOther {
			t.Fatalf("matching dashboard callback status=%d, want 303", response.StatusCode)
		}
		if cookies := client.Jar.Cookies(callbackURL); hasCookie(cookies, "__Host-kauth_dashboard_login") {
			t.Fatalf("matching callback retained dashboard login cookie: %#v", cookies)
		}

		noEmailClient, noEmailState, noEmailChallenge := environment.dashboardLoginStart(t)
		noEmailCallback := environment.proxyURL + "/callback?state=" + url.QueryEscape(noEmailState) + "&code=" + url.QueryEscape("dashboard-no-email-code."+noEmailChallenge)
		response, err = noEmailClient.Get(noEmailCallback)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusForbidden {
			t.Fatalf("missing-email callback status=%d, want 403", response.StatusCode)
		}

		response, err = client.Get(environment.proxyURL + "/sessions/" + url.PathEscape(environment.sessionID) + "?page=101")
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("deep pagination status=%d, want 400", response.StatusCode)
		}

		response, err = client.Get(environment.proxyURL + "/")
		if err != nil {
			t.Fatal(err)
		}
		page, _ = io.ReadAll(response.Body)
		_ = response.Body.Close()
		csrf := hiddenValue(string(page), "csrf")
		if csrf == "" {
			t.Fatal("dashboard page omitted CSRF token")
		}
		response, err = client.Post(environment.proxyURL+"/logout", "application/x-www-form-urlencoded", strings.NewReader("csrf="+url.QueryEscape(csrf)))
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusSeeOther {
			t.Fatalf("valid logout status=%d, want 303", response.StatusCode)
		}
		if response.Header.Get("Location") != "/" {
			t.Fatalf("logout location=%q, want /", response.Header.Get("Location"))
		}
		response, err = client.Get(environment.proxyURL + "/")
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("logged-out dashboard status=%d, want sign-in page", response.StatusCode)
		}
	})

	t.Run("database migrations are idempotent and retention deletes old events", func(t *testing.T) {
		port, command, output, err := environment.clusterPortForward(kauthNamespace, "service/postgres", 5432)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = command.Process.Kill(); _ = command.Wait() }()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		store, err := audit.NewPostgresStore(ctx, fmt.Sprintf("postgres://kauth:kauth@127.0.0.1:%d/kauth?sslmode=disable", port), 16, time.Hour)
		if err != nil {
			t.Fatalf("second migration/startup failed: %v; port-forward=%s", err, output.String())
		}
		defer func() { _ = store.Close(context.Background()) }()
		store.Record(audit.RequestEvent{
			OccurredAt: time.Now().Add(-2 * time.Hour), Cluster: "retention-e2e",
			RequestID: "retention-event", SessionID: "retention-session", Username: testUser,
			Groups: []string{}, Authenticated: true, Method: http.MethodGet, Path: "/expired",
			StatusCode: http.StatusOK,
		})
		deadline := time.Now().Add(10 * time.Second)
		for {
			metrics, metricErr := store.GlobalMetrics(ctx, "retention-e2e", time.Now().Add(-3*time.Hour))
			if metricErr == nil && metrics.Requests == 1 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("old event was not persisted: metrics=%#v error=%v", metrics, metricErr)
			}
			time.Sleep(100 * time.Millisecond)
		}
		if err := store.RunRetention(ctx, time.Now()); err != nil {
			t.Fatal(err)
		}
		metrics, err := store.GlobalMetrics(ctx, "retention-e2e", time.Now().Add(-3*time.Hour))
		if err != nil || metrics.Requests != 0 {
			t.Fatalf("retention metrics=%#v error=%v", metrics, err)
		}
	})

	t.Run("database outage blocks auth and proxy recovers once Postgres is back", func(t *testing.T) {
		// Postgres is a hard dependency for auth now, so an outage means 401, not 404.
		environment.clusterKubectl(t, "--namespace", kauthNamespace, "scale", "statefulset/postgres", "--replicas=0")
		environment.waitForNoPods(t, kauthNamespace, "app=postgres")

		if status := environment.apiRequest(t, "/api/v1/namespaces/kauth-e2e/configmaps/db-outage-prime"); status != http.StatusUnauthorized {
			t.Fatalf("proxy status during DB outage=%d, want 401", status)
		}
		time.Sleep(500 * time.Millisecond)
		statuses := make(chan int, 64)
		var wait sync.WaitGroup
		for i := range 64 {
			wait.Add(1)
			go func() {
				defer wait.Done()
				statuses <- environment.apiRequest(t, fmt.Sprintf("/api/v1/namespaces/kauth-e2e/configmaps/db-outage-%d", i))
			}()
		}
		wait.Wait()
		close(statuses)
		for status := range statuses {
			if status != http.StatusUnauthorized {
				t.Errorf("proxy status during DB outage=%d, want 401", status)
			}
		}

		environment.clusterKubectl(t, "--namespace", kauthNamespace, "scale", "statefulset/postgres", "--replicas=1")
		environment.clusterKubectl(t, "--namespace", kauthNamespace, "rollout", "status", "statefulset/postgres", "--timeout=120s")
		environment.restartSessionClient(t)
		client := environment.dashboardClient(t, "dashboard-user-code")
		environment.waitForRecoveredRequest(t, client, "db-recovered-1")

		environment.clusterKubectl(t, "--namespace", kauthNamespace, "delete", "pod/postgres-0", "--wait=true")
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()
		if err := environment.waitForPodReady(ctx, kauthNamespace, "postgres-0"); err != nil {
			t.Fatal(err)
		}
		environment.restartSessionClient(t)
		environment.waitForRecoveredRequest(t, client, "db-recovered-2")
	})

	t.Run("rolling restart preserves sessions and flushes audit", func(t *testing.T) {
		marker := "/api/v1/namespaces/kauth-e2e/configmaps/shutdown-flush"
		if status := environment.apiRequest(t, marker); status != http.StatusNotFound {
			t.Fatalf("marker status=%d, want 404", status)
		}
		environment.clusterKubectl(t, "--namespace", kauthNamespace, "rollout", "restart", "deployment/kauth-server")
		environment.clusterKubectl(t, "--namespace", kauthNamespace, "rollout", "status", "deployment/kauth-server", "--timeout=180s")
		environment.stopPortForward()
		if err := environment.startPortForward(); err != nil {
			t.Fatal(err)
		}
		if output := environment.kubectl(t, "get", "--raw", "/version"); !strings.Contains(output, `"gitVersion"`) {
			t.Fatalf("session did not survive restart: %s", output)
		}
		client := environment.dashboardClient(t, "dashboard-user-code")
		environment.waitDashboardContains(t, client, marker)
	})

	t.Run("revocation is immediate", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := environment.sessionClient.Revoke(ctx, environment.sessionID); err != nil {
			t.Fatal(err)
		}
		revoked, err := environment.sessionClient.Get(ctx, environment.sessionID)
		if err != nil {
			t.Fatal(err)
		}
		if revoked.APIToken != "" || revoked.RefreshToken != "" {
			t.Fatal("revocation did not scrub stored credentials")
		}
		output, err := environment.kubectlCommand("get", "configmaps")
		lowerOutput := strings.ToLower(output)
		if err == nil || (!strings.Contains(lowerOutput, "unauthorized") && !strings.Contains(lowerOutput, "credentials")) {
			t.Fatalf("revoked request error = %v, output = %s", err, output)
		}
	})
}

func (e *e2eEnvironment) kubectl(t *testing.T, args ...string) string {
	t.Helper()
	output, err := e.kubectlCommand(args...)
	if err != nil {
		t.Fatalf("kubectl %s: %v\n%s", strings.Join(args, " "), err, output)
	}
	return strings.TrimSpace(output)
}

func (e *e2eEnvironment) dashboardClient(t *testing.T, code string) *http.Client {
	t.Helper()
	client, state, challenge := e.dashboardLoginStart(t)
	callback := e.proxyURL + "/callback?state=" + url.QueryEscape(state) + "&code=" + url.QueryEscape(code+"."+challenge)
	response, err := client.Get(callback)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusSeeOther || response.Header.Get("Location") != "/" {
		t.Fatalf("dashboard callback = %d %q", response.StatusCode, response.Header.Get("Location"))
	}
	return client
}

func (e *e2eEnvironment) dashboardLoginStart(t *testing.T) (*http.Client, string, string) {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := e.dashboardHTTPClient(jar)
	response, err := client.Get(e.proxyURL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusFound {
		t.Fatalf("dashboard login status = %d", response.StatusCode)
	}
	authorizationURL, err := url.Parse(response.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	state := authorizationURL.Query().Get("state")
	challenge := authorizationURL.Query().Get("code_challenge")
	if challenge == "" || authorizationURL.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("dashboard authorization URL has invalid PKCE challenge: %s", authorizationURL)
	}
	if authorizationURL.Query().Get("access_type") == "offline" || strings.Contains(authorizationURL.Query().Get("scope"), "offline_access") {
		t.Fatalf("dashboard authorization requested offline access: %s", authorizationURL)
	}
	if state == "" {
		t.Fatal("dashboard authorization URL has no state")
	}
	return client, state, challenge
}

func (e *e2eEnvironment) dashboardHTTPClient(jar http.CookieJar) *http.Client {
	return &http.Client{
		Transport: e.proxyServer.Client().Transport,
		Jar:       jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (e *e2eEnvironment) apiRequest(t *testing.T, path string) int {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, e.proxyURL+"/k8s"+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+e.apiToken)
	response, err := e.proxyServer.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	return response.StatusCode
}

// Sends fresh markers (a dropped one never reappears) and checks the previous attempt's, giving the flush tick time to land it.
func (e *e2eEnvironment) waitForRecoveredRequest(t *testing.T, client *http.Client, prefix string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	var lastStatus int
	var prevMarker string
	for attempt := 0; ; attempt++ {
		marker := fmt.Sprintf("/api/v1/namespaces/kauth-e2e/configmaps/%s-%d", prefix, attempt)
		lastStatus = e.apiRequest(t, marker)
		if prevMarker != "" {
			response, err := client.Get(e.proxyURL + "/sessions/" + url.PathEscape(e.sessionID))
			if err == nil {
				body, _ := io.ReadAll(response.Body)
				_ = response.Body.Close()
				if response.StatusCode == http.StatusOK && strings.Contains(string(body), prevMarker) {
					return
				}
			}
		}
		if lastStatus == http.StatusNotFound {
			prevMarker = marker
		}
		if time.Now().After(deadline) {
			t.Fatalf("no %s-* marker appeared in the dashboard within the deadline (last proxy status=%d)", prefix, lastStatus)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func (e *e2eEnvironment) waitDashboardContains(t *testing.T, client *http.Client, expected string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		response, err := client.Get(e.proxyURL + "/sessions/" + url.PathEscape(e.sessionID))
		if err == nil {
			body, _ := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK && strings.Contains(string(body), expected) {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("dashboard did not contain %q", expected)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func (e *e2eEnvironment) waitForNoPods(t *testing.T, namespace, selector string) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		pods, err := e.clientset.CoreV1().Pods(namespace).List(context.Background(), metav1.ListOptions{LabelSelector: selector})
		if err == nil && len(pods.Items) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("pods with selector %q were not removed", selector)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func hiddenValue(page, name string) string {
	marker := `name="` + name + `" value="`
	start := strings.Index(page, marker)
	if start < 0 {
		return ""
	}
	start += len(marker)
	end := strings.IndexByte(page[start:], '"')
	if end < 0 {
		return ""
	}
	return page[start : start+end]
}

func hasCookie(cookies []*http.Cookie, name string) bool {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return true
		}
	}
	return false
}

func (e *e2eEnvironment) refresh(t *testing.T, refreshToken string) (string, int, string) {
	t.Helper()
	token, status, body, err := e.refreshRequest(refreshToken)
	if err != nil {
		t.Fatal(err)
	}
	return token, status, body
}

func (e *e2eEnvironment) refreshRequest(refreshToken string) (string, int, string, error) {
	payload, err := json.Marshal(map[string]string{"refresh_token": refreshToken})
	if err != nil {
		return "", 0, "", err
	}
	response, err := e.proxyServer.Client().Post(e.proxyURL+"/api/refresh", "application/json", bytes.NewReader(payload))
	if err != nil {
		return "", 0, "", err
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	var result struct {
		RefreshToken string `json:"refresh_token"`
	}
	_ = json.Unmarshal(body, &result)
	return result.RefreshToken, response.StatusCode, string(body), nil
}

func (e *e2eEnvironment) requestThroughPod(podName string) error {
	port, err := availablePort()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "kubectl", "--kubeconfig", e.clusterConfig, "--namespace", kauthNamespace, "port-forward", "pod/"+podName, fmt.Sprintf("%d:8080", port))
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		return err
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()

	deadline := time.Now().Add(10 * time.Second)
	for {
		request, requestErr := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/k8s/version", port), nil)
		if requestErr != nil {
			return requestErr
		}
		request.Header.Set("Authorization", "Bearer "+e.apiToken)
		response, requestErr := http.DefaultClient.Do(request)
		if requestErr == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("port-forward did not become ready: %s", output.String())
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func (e *e2eEnvironment) clusterPortForward(namespace, resource string, remotePort int) (int, *exec.Cmd, *bytes.Buffer, error) {
	port, err := availablePort()
	if err != nil {
		return 0, nil, nil, err
	}
	cmd := exec.Command("kubectl", "--kubeconfig", e.clusterConfig, "--namespace", namespace, "port-forward", resource, fmt.Sprintf("%d:%d", port, remotePort))
	output := &bytes.Buffer{}
	cmd.Stdout = output
	cmd.Stderr = output
	if err := cmd.Start(); err != nil {
		return 0, nil, output, err
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		connection, dialErr := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond)
		if dialErr == nil {
			_ = connection.Close()
			return port, cmd, output, nil
		}
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return 0, nil, output, fmt.Errorf("port-forward failed: %s", output.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (e *e2eEnvironment) kubectlCommand(args ...string) (string, error) {
	allArgs := append([]string{"--kubeconfig", e.kubectlConfig}, args...)
	cmd := exec.Command("kubectl", allArgs...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func (e *e2eEnvironment) clusterKubectl(t *testing.T, args ...string) string {
	t.Helper()
	allArgs := append([]string{"--kubeconfig", e.clusterConfig}, args...)
	output, err := e.run("kubectl", allArgs...)
	if err != nil {
		t.Fatal(err)
	}
	return output
}

func (e *e2eEnvironment) run(command string, args ...string) (string, error) {
	cmd := exec.Command(command, args...)
	cmd.Dir = e.repoRoot
	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("%s %s: %w\n%s", command, strings.Join(args, " "), err, output)
	}
	return string(output), nil
}

func (e *e2eEnvironment) cleanup() error {
	if e == nil {
		return nil
	}
	e.stopPortForward()
	e.stopDBPortForward()
	if e.proxyServer != nil {
		e.proxyServer.Close()
	}
	var cleanupErr error
	if e.clusterName != "" && os.Getenv("KAUTH_E2E_KEEP_CLUSTER") == "" {
		if _, err := e.run("kind", "delete", "cluster", "--name", e.clusterName); err != nil {
			cleanupErr = err
		}
	}
	if os.Getenv("KAUTH_E2E_KEEP_CLUSTER") == "" {
		if e.image != "" {
			_, _ = e.run("docker", "image", "rm", e.image)
		}
		_ = os.RemoveAll(e.tempDir)
	} else {
		fmt.Fprintf(os.Stderr, "Kept E2E cluster %s and artifacts %s\n", e.clusterName, e.tempDir)
	}
	return cleanupErr
}

func availablePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}
