# kauth - Kubernetes OIDC Authentication

Simple, production-ready Kubernetes SSO with Authentik and OIDC.

## User Experience

```bash
kauth login --url https://kauth.example.com
```

**That's it!** Browser opens, you authenticate, kubeconfig is saved automatically.

## Architecture

- **kauth-server**: Web service running in Kubernetes that handles OAuth2/OIDC flows
- **kauth CLI**: Simple client that opens browser and waits for completion via SSE
- **Authentik**: Your OIDC identity provider
- **Kubernetes API**: Validates ID tokens cryptographically

### Flow

1. User runs `kauth login --url https://kauth.example.com`
2. CLI calls `/start-login`, gets session ID
3. Browser opens to Authentik for authentication
4. CLI watches `/watch?session=XXX` (Server-Sent Events)
5. User completes auth, server notifies CLI instantly via SSE
6. Kubeconfig automatically saved to `~/.kube/config`
7. Done! `kubectl get pods` works immediately

## Building

### With Nix

```bash
# Build CLI
nix build .#cli

# Build server
nix build .#server

# Build Docker image
nix build .#docker

# Development shell
nix develop

# Run directly
nix run .#kauth -- login --url https://kauth.example.com
```

### With Make

```bash
# Build both
make build

# Build CLI only
make build-cli

# Build server only
make build-server

# Cross-compile for all platforms
make build-all

# Docker image
make docker-build
```

### With Go

```bash
CGO_ENABLED=0 go build -o kauth ./cmd/kauth
CGO_ENABLED=0 go build -o kauth-server ./cmd/kauth-server
```

## Deployment

### Deploy to Kubernetes

```bash
# Edit deploy/kubernetes/deployment.yaml with your settings
kubectl apply -f deploy/kubernetes/deployment.yaml

# Setup RBAC
kubectl apply -f deploy/kubernetes/rbac.yaml
```

### Using NixOS Module

```nix
{
  inputs.kauth.url = "github:yourusername/kauth";

  services.kauth = {
    enable = true;
    baseURL = "https://kauth.example.com";
    oidc = {
      issuerURL = "https://authentik.example.com/application/o/kube-apiserver/";
      clientID = "kube-apiserver";
      clientSecretFile = "/run/secrets/oidc-client-secret";
    };
    cluster = {
      name = "production";
      server = "https://k8s.example.com:6443";
      caDataFile = "/run/secrets/cluster-ca";
    };
  };
}
```

## Configuration

### Kubernetes API Server

Add these flags:

```bash
--oidc-issuer-url=https://authentik.example.com/application/o/kube-apiserver/
--oidc-client-id=kube-apiserver
--oidc-username-claim=email
--oidc-groups-claim=groups
--oidc-username-prefix=oidc:
--oidc-groups-prefix=oidc:
```

### Authentik

1. Create OAuth2/OIDC Provider:
   - Client ID: `kube-apiserver`
   - Redirect URI: `https://kauth.example.com/callback`
   - Scopes: `openid`, `email`, `profile`, `groups`, `offline_access`

2. Create groups: `k8s-admins`, `developers`, `viewers`

3. Assign users to groups

## Features

✅ **Server-Sent Events (SSE)** - Instant completion notification, no polling  
✅ **OAuth2 PKCE** - Secure authorization code flow  
✅ **Automatic kubeconfig** - No manual copy/paste needed  
✅ **Group-based RBAC** - Map Authentik groups to Kubernetes roles  
✅ **Session security** - HttpOnly cookies, CSRF protection  
✅ **Nix flake** - Reproducible builds, NixOS module included  
✅ **Production ready** - Kubernetes deployment, health checks, resource limits  

## Project Structure

```
kauth/
├── cmd/
│   ├── kauth/          # CLI client
│   └── kauth-server/   # Web service
├── pkg/
│   ├── oauth/          # OAuth2/OIDC implementation
│   ├── handlers/       # HTTP handlers (SSE, login, callback)
│   ├── token/          # Secure token storage
│   ├── browser/        # Cross-platform browser opening
│   └── kubeconfig/     # Kubeconfig generation
├── deploy/
│   └── kubernetes/     # Deployment manifests, Dockerfile
├── flake.nix           # Nix flake
└── Makefile           # Build targets
```

## License

MIT
