package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

func TestGetKubeconfigInfoUsesKubeconfigEnvironment(t *testing.T) {
	config := clientcmdapi.NewConfig()
	config.Clusters["custom-cluster"] = &clientcmdapi.Cluster{Server: "https://custom.example"}
	config.AuthInfos["custom-user"] = &clientcmdapi.AuthInfo{Exec: &clientcmdapi.ExecConfig{
		Command: "kauth",
		Args:    []string{"get-token", "--profile", "0123456789abcdef"},
	}}
	config.Contexts["custom-context"] = &clientcmdapi.Context{Cluster: "custom-cluster", AuthInfo: "custom-user"}
	config.CurrentContext = "custom-context"

	path := filepath.Join(t.TempDir(), "custom-kubeconfig")
	data, err := clientcmd.Write(*config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBECONFIG", path)

	info, err := getKubeconfigInfo()
	if err != nil {
		t.Fatal(err)
	}
	if info.contextName != "custom-context" || info.profile != "0123456789abcdef" || info.apiServer != "https://custom.example" {
		t.Errorf("getKubeconfigInfo() = %+v", info)
	}
}
