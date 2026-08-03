package handlers

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestKubeconfigGeneratorUsesProxyEndpoint(t *testing.T) {
	generator := KubeconfigGenerator{
		ClusterName:   "production",
		ClusterServer: "https://kauth.example.com",
	}
	generated := generator.Generate(`user"name@example.com`, `user"name`)

	var config map[string]any
	if err := yaml.Unmarshal([]byte(generated), &config); err != nil {
		t.Fatalf("generated kubeconfig is invalid: %v\n%s", err, generated)
	}
	if !strings.Contains(generated, `server: "https://kauth.example.com"`) {
		t.Fatalf("proxy endpoint missing:\n%s", generated)
	}
	if strings.Contains(generated, "certificate-authority") {
		t.Fatalf("upstream CA leaked into kubeconfig:\n%s", generated)
	}
	if !strings.Contains(generated, "command: kauth") || !strings.Contains(generated, "- get-token") {
		t.Fatalf("exec credential missing:\n%s", generated)
	}
}
