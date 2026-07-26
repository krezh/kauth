package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

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
