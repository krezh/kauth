package cmd

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"kauth/pkg/token"

	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

func testJWT(exp time.Time) string {
	payload, _ := json.Marshal(map[string]int64{"exp": exp.Unix()})
	return "e30." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}

func TestEnsureFreshIDTokenRetriesRequestID(t *testing.T) {
	var requestIDs []string
	attempt := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req RefreshRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		requestIDs = append(requestIDs, req.RequestID)
		attempt++
		if attempt == 1 {
			http.Error(w, "lost response", http.StatusInternalServerError)
			return
		}
		writeJSON := json.NewEncoder(w)
		_ = writeJSON.Encode(RefreshResponse{IDToken: testJWT(time.Now().Add(time.Hour)), RefreshToken: "new-refresh"})
	}))
	defer server.Close()

	storage := token.NewStorage(filepath.Join(t.TempDir(), "token.json"))
	cache := &token.Cache{ServerURL: server.URL, RefreshToken: "old-refresh"}
	if err := storage.Save(cache); err != nil {
		t.Fatal(err)
	}
	if err := ensureFreshIDToken(storage, cache); err == nil {
		t.Fatal("first refresh unexpectedly succeeded")
	}
	pending, err := storage.Load()
	if err != nil || pending.RefreshRequestID == "" {
		t.Fatalf("pending request was not persisted: cache=%+v err=%v", pending, err)
	}
	if err := ensureFreshIDToken(storage, cache); err != nil {
		t.Fatalf("retry failed: %v", err)
	}
	if len(requestIDs) != 2 || requestIDs[0] == "" || requestIDs[0] != requestIDs[1] {
		t.Errorf("request IDs = %v, want the same non-empty ID", requestIDs)
	}
	updated, err := storage.Load()
	if err != nil {
		t.Fatal(err)
	}
	if updated.RefreshToken != "new-refresh" || updated.IDToken == "" || updated.RefreshRequestID != "" {
		t.Errorf("updated cache = %+v", updated)
	}
}

func TestEnsureFreshIDTokenReplacesExpiredReplay(t *testing.T) {
	attempt := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt++
		expiry := time.Now().Add(-time.Minute)
		if attempt == 2 {
			expiry = time.Now().Add(time.Hour)
		}
		_ = json.NewEncoder(w).Encode(RefreshResponse{
			IDToken:      testJWT(expiry),
			RefreshToken: fmt.Sprintf("refresh-%d", attempt),
		})
	}))
	defer server.Close()

	storage := token.NewStorage(filepath.Join(t.TempDir(), "token.json"))
	cache := &token.Cache{ServerURL: server.URL, RefreshToken: "old-refresh", RefreshRequestID: "request-id-0123456789"}
	if err := storage.Save(cache); err != nil {
		t.Fatal(err)
	}
	if err := ensureFreshIDToken(storage, cache); err != nil {
		t.Fatal(err)
	}
	if attempt != 2 || cache.RefreshToken != "refresh-2" {
		t.Errorf("attempts = %d, cache = %+v", attempt, cache)
	}
}

func TestEnsureFreshIDTokenRejectsChangedSession(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		http.Error(w, "unexpected request", http.StatusInternalServerError)
	}))
	defer server.Close()

	storage := token.NewStorage(filepath.Join(t.TempDir(), "token.json"))
	oldCache := &token.Cache{ServerURL: server.URL, SessionID: "old-session", RefreshToken: "old-refresh"}
	if err := storage.Save(&token.Cache{ServerURL: server.URL, SessionID: "new-session", RefreshToken: "new-refresh"}); err != nil {
		t.Fatal(err)
	}
	if err := ensureFreshIDToken(storage, oldCache); err == nil {
		t.Fatal("ensureFreshIDToken() accepted a replaced session")
	}
	if requests != 0 || oldCache.SessionID != "old-session" {
		t.Errorf("requests = %d, cache = %+v", requests, oldCache)
	}
}

func TestValidateRemoteKubeconfig(t *testing.T) {
	valid := clientcmdapi.NewConfig()
	valid.APIVersion = "v1"
	valid.Kind = "Config"
	valid.Clusters["cluster"] = &clientcmdapi.Cluster{Server: "https://cluster.example", CertificateAuthorityData: []byte("ca")}
	valid.AuthInfos["user"] = &clientcmdapi.AuthInfo{Exec: &clientcmdapi.ExecConfig{
		APIVersion: "client.authentication.k8s.io/v1", Command: "kauth", Args: []string{"get-token"},
		InteractiveMode: clientcmdapi.NeverExecInteractiveMode,
	}}
	valid.Contexts["context"] = &clientcmdapi.Context{Cluster: "cluster", AuthInfo: "user", Namespace: "default"}
	valid.CurrentContext = "context"
	if err := validateRemoteKubeconfig(valid); err != nil {
		t.Fatalf("validateRemoteKubeconfig() error = %v", err)
	}

	for name, exec := range map[string]*clientcmdapi.ExecConfig{
		"command": {APIVersion: "client.authentication.k8s.io/v1", Command: "/bin/sh", Args: []string{"get-token"}, InteractiveMode: clientcmdapi.NeverExecInteractiveMode},
		"args":    {APIVersion: "client.authentication.k8s.io/v1", Command: "kauth", Args: []string{"login"}, InteractiveMode: clientcmdapi.NeverExecInteractiveMode},
		"env":     {APIVersion: "client.authentication.k8s.io/v1", Command: "kauth", Args: []string{"get-token"}, Env: []clientcmdapi.ExecEnvVar{{Name: "PATH", Value: "/tmp"}}, InteractiveMode: clientcmdapi.NeverExecInteractiveMode},
	} {
		t.Run(name, func(t *testing.T) {
			config := valid.DeepCopy()
			config.AuthInfos["user"].Exec = exec
			if err := validateRemoteKubeconfig(config); err == nil {
				t.Error("validateRemoteKubeconfig() accepted unsafe exec configuration")
			}
		})
	}
}

func TestSetKubeconfigProfile(t *testing.T) {
	config := clientcmdapi.NewConfig()
	config.AuthInfos["user"] = &clientcmdapi.AuthInfo{Exec: &clientcmdapi.ExecConfig{
		Command: "kauth",
		Args:    []string{"get-token"},
	}}
	config.Contexts["context"] = &clientcmdapi.Context{AuthInfo: "user"}
	setKubeconfigProfile(config, "0123456789abcdef")
	want := []string{"get-token", "--profile", "0123456789abcdef"}
	profiledUser := "user@0123456789abcdef"
	if !reflect.DeepEqual(config.AuthInfos[profiledUser].Exec.Args, want) {
		t.Errorf("exec args = %v, want %v", config.AuthInfos[profiledUser].Exec.Args, want)
	}
	if config.Contexts["context"].AuthInfo != profiledUser || config.AuthInfos["user"] != nil {
		t.Errorf("profiled auth info was not isolated: %+v", config)
	}
}

func TestWriteKubeconfigAtomicPreservesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "config")
	if err := os.WriteFile(target, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	config := clientcmdapi.NewConfig()
	config.Clusters["cluster"] = &clientcmdapi.Cluster{Server: "https://cluster.example"}
	if err := writeKubeconfigAtomic(link, config); err != nil {
		t.Fatalf("writeKubeconfigAtomic() error = %v", err)
	}
	if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Errorf("kubeconfig symlink was replaced: info=%v err=%v", info, err)
	}
	if _, err := clientcmd.LoadFromFile(target); err != nil {
		t.Errorf("symlink target was not updated with valid kubeconfig: %v", err)
	}
}

func TestWriteKubeconfigAtomicCreatesDanglingSymlinkTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "config")
	if err := os.Symlink("target", link); err != nil {
		t.Fatal(err)
	}
	config := clientcmdapi.NewConfig()
	config.Clusters["cluster"] = &clientcmdapi.Cluster{Server: "https://cluster.example"}
	if err := writeKubeconfigAtomic(link, config); err != nil {
		t.Fatalf("writeKubeconfigAtomic() error = %v", err)
	}
	if _, err := clientcmd.LoadFromFile(target); err != nil {
		t.Errorf("dangling symlink target was not created: %v", err)
	}
}

func TestMergeKubeconfigPreservesFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	existing := `apiVersion: v1
kind: Config
clusters:
- name: existing
  cluster:
    server: https://existing.example
    tls-server-name: api.internal
    proxy-url: https://proxy.example
users:
- name: existing
  user:
    tokenFile: /tmp/token
contexts:
- name: existing
  context:
    cluster: existing
    user: existing
current-context: existing
`
	if err := os.WriteFile(path, []byte(existing), 0600); err != nil {
		t.Fatal(err)
	}
	incoming := clientcmdapi.NewConfig()
	incoming.Clusters["new"] = &clientcmdapi.Cluster{Server: "https://new.example"}
	incoming.AuthInfos["new"] = &clientcmdapi.AuthInfo{Exec: &clientcmdapi.ExecConfig{Command: "kauth", Args: []string{"get-token"}}}
	incoming.Contexts["new"] = &clientcmdapi.Context{Cluster: "new", AuthInfo: "new"}
	incoming.CurrentContext = "new"

	if err := mergeKubeconfig(path, incoming); err != nil {
		t.Fatalf("mergeKubeconfig() error = %v", err)
	}
	got, err := clientcmd.LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Clusters["existing"].TLSServerName != "api.internal" || got.Clusters["existing"].ProxyURL != "https://proxy.example" {
		t.Error("mergeKubeconfig() discarded existing cluster fields")
	}
	if got.AuthInfos["existing"].TokenFile != "/tmp/token" {
		t.Error("mergeKubeconfig() discarded existing auth fields")
	}
	if got.CurrentContext != "new" || got.Clusters["new"] == nil || got.AuthInfos["new"] == nil || got.Contexts["new"] == nil {
		t.Error("mergeKubeconfig() did not merge incoming configuration")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("kubeconfig mode = %o, want 600", info.Mode().Perm())
	}
	matches, err := filepath.Glob(filepath.Join(dir, ".kauth-kubeconfig-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Errorf("temporary kubeconfig files remain: %v", matches)
	}
}

func TestHasConflictUsesIncomingNames(t *testing.T) {
	existing := []byte(`apiVersion: v1
kind: Config
clusters:
- name: production
  cluster:
    server: https://existing.example
users: []
contexts: []
`)
	incoming := clientcmdapi.NewConfig()
	incoming.Clusters["production"] = &clientcmdapi.Cluster{Server: "https://replacement.example"}
	if !hasConflict(existing, incoming) {
		t.Error("hasConflict() missed an incoming name collision")
	}
}

func TestUpdateKubeconfigSerializesConcurrentMerges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	configs := []*clientcmdapi.Config{clientcmdapi.NewConfig(), clientcmdapi.NewConfig()}
	for i, config := range configs {
		name := fmt.Sprintf("cluster-%d", i)
		config.Clusters[name] = &clientcmdapi.Cluster{Server: "https://" + name + ".example"}
		config.AuthInfos[name] = &clientcmdapi.AuthInfo{Token: name}
		config.Contexts[name] = &clientcmdapi.Context{Cluster: name, AuthInfo: name}
	}

	var wg sync.WaitGroup
	errs := make(chan error, len(configs))
	for _, config := range configs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := updateKubeconfig(path, config, "unique")
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	merged, err := clientcmd.LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(merged.Clusters) != 2 || len(merged.Contexts) != 2 || len(merged.AuthInfos) != 2 {
		t.Errorf("concurrent merge lost entries: %+v", merged)
	}
}

func TestValidateServerURL(t *testing.T) {
	got, err := validateServerURL("https://kauth.example.com/")
	if err != nil || got != "https://kauth.example.com" {
		t.Fatalf("validateServerURL() = %q, %v", got, err)
	}
	for _, rawURL := range []string{
		"http://kauth.example.com",
		"https://user@kauth.example.com",
		"https://kauth.example.com?redirect=evil",
		"file:///tmp/kauth",
	} {
		if _, err := validateServerURL(rawURL); err == nil {
			t.Errorf("validateServerURL(%q) accepted unsafe URL", rawURL)
		}
	}
}
