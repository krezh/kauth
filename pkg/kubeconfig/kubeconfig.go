package kubeconfig

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// UpdateConfig holds configuration for kubeconfig updates
type UpdateConfig struct {
	KubeconfigPath string
	ClusterName    string
	ClusterServer  string
	ClusterCA      string
	UserName       string
	ContextName    string
	IssuerURL      string
	ClientID       string
	ClientSecret   string
	KauthPath      string
	CallbackPort   int
}

// Kubeconfig represents a Kubernetes config file
type Kubeconfig struct {
	APIVersion     string         `yaml:"apiVersion"`
	Kind           string         `yaml:"kind"`
	CurrentContext string         `yaml:"current-context,omitempty"`
	Clusters       []NamedCluster `yaml:"clusters"`
	Contexts       []NamedContext `yaml:"contexts"`
	Users          []NamedUser    `yaml:"users"`
}

type NamedCluster struct {
	Name    string  `yaml:"name"`
	Cluster Cluster `yaml:"cluster"`
}

type Cluster struct {
	Server                   string `yaml:"server"`
	CertificateAuthorityData string `yaml:"certificate-authority-data,omitempty"`
	CertificateAuthority     string `yaml:"certificate-authority,omitempty"`
	InsecureSkipTLSVerify    bool   `yaml:"insecure-skip-tls-verify,omitempty"`
}

type NamedContext struct {
	Name    string  `yaml:"name"`
	Context Context `yaml:"context"`
}

type Context struct {
	Cluster   string `yaml:"cluster"`
	User      string `yaml:"user"`
	Namespace string `yaml:"namespace,omitempty"`
}

type NamedUser struct {
	Name string `yaml:"name"`
	User User   `yaml:"user"`
}

type User struct {
	Exec *ExecConfig `yaml:"exec,omitempty"`
}

type ExecConfig struct {
	APIVersion      string   `yaml:"apiVersion"`
	Command         string   `yaml:"command"`
	Args            []string `yaml:"args"`
	InteractiveMode string   `yaml:"interactiveMode,omitempty"`
}

// UpdateKubeconfig updates the kubeconfig file with kauth configuration
func UpdateKubeconfig(cfg UpdateConfig) error {
	// Create .kube directory if it doesn't exist
	kubedir := filepath.Dir(cfg.KubeconfigPath)
	if err := os.MkdirAll(kubedir, 0755); err != nil {
		return fmt.Errorf("failed to create .kube directory: %w", err)
	}

	// Load existing kubeconfig or create new one
	kubeconfig, err := loadKubeconfig(cfg.KubeconfigPath)
	if err != nil {
		// Create new kubeconfig
		kubeconfig = &Kubeconfig{
			APIVersion: "v1",
			Kind:       "Config",
			Clusters:   []NamedCluster{},
			Contexts:   []NamedContext{},
			Users:      []NamedUser{},
		}
	}

	// Add or update cluster (only if server is provided)
	if cfg.ClusterServer != "" {
		cluster := Cluster{
			Server: cfg.ClusterServer,
		}

		if cfg.ClusterCA != "" {
			// Read CA file and base64 encode
			caData, err := os.ReadFile(cfg.ClusterCA)
			if err != nil {
				return fmt.Errorf("failed to read cluster CA: %w", err)
			}
			cluster.CertificateAuthorityData = base64.StdEncoding.EncodeToString(caData)
		}

		kubeconfig.upsertCluster(cfg.ClusterName, cluster)
	}

	// Build exec args
	args := []string{
		"get-token",
		"--issuer-url=" + cfg.IssuerURL,
		"--client-id=" + cfg.ClientID,
	}

	if cfg.ClientSecret != "" {
		args = append(args, "--client-secret="+cfg.ClientSecret)
	}

	if cfg.CallbackPort != 8000 {
		args = append(args, fmt.Sprintf("--callback-port=%d", cfg.CallbackPort))
	}

	// Add or update user with exec credential plugin
	user := User{
		Exec: &ExecConfig{
			APIVersion:      "client.authentication.k8s.io/v1",
			Command:         cfg.KauthPath,
			Args:            args,
			InteractiveMode: "IfAvailable",
		},
	}
	kubeconfig.upsertUser(cfg.UserName, user)

	// Add or update context
	context := Context{
		Cluster: cfg.ClusterName,
		User:    cfg.UserName,
	}
	kubeconfig.upsertContext(cfg.ContextName, context)

	// Save kubeconfig
	return saveKubeconfig(cfg.KubeconfigPath, kubeconfig)
}

func loadKubeconfig(path string) (*Kubeconfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var kubeconfig Kubeconfig
	if err := yaml.Unmarshal(data, &kubeconfig); err != nil {
		return nil, fmt.Errorf("failed to parse kubeconfig: %w", err)
	}

	return &kubeconfig, nil
}

func saveKubeconfig(path string, kubeconfig *Kubeconfig) error {
	data, err := yaml.Marshal(kubeconfig)
	if err != nil {
		return fmt.Errorf("failed to marshal kubeconfig: %w", err)
	}

	// Write with 0600 permissions (read/write for owner only)
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write kubeconfig: %w", err)
	}

	return nil
}

func (k *Kubeconfig) upsertCluster(name string, cluster Cluster) {
	for i, c := range k.Clusters {
		if c.Name == name {
			k.Clusters[i].Cluster = cluster
			return
		}
	}
	k.Clusters = append(k.Clusters, NamedCluster{
		Name:    name,
		Cluster: cluster,
	})
}

func (k *Kubeconfig) upsertUser(name string, user User) {
	for i, u := range k.Users {
		if u.Name == name {
			k.Users[i].User = user
			return
		}
	}
	k.Users = append(k.Users, NamedUser{
		Name: name,
		User: user,
	})
}

func (k *Kubeconfig) upsertContext(name string, context Context) {
	for i, c := range k.Contexts {
		if c.Name == name {
			k.Contexts[i].Context = context
			return
		}
	}
	k.Contexts = append(k.Contexts, NamedContext{
		Name:    name,
		Context: context,
	})
}
