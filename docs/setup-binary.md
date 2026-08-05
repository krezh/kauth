# Binary setup

Use the server binary for local development or a directly managed host.

## Prerequisites

- A PostgreSQL database
- An OIDC client
- A kubeconfig for the cluster kauth will proxy

The kubeconfig identity needs cluster-scoped `impersonate` access to core
`users` and `groups`.

Register this OIDC redirect URI:

```text
https://kauth.example.com/callback
```

## Install

Download `kauth` and `kauth-server` from the GitHub release, or install the Nix
packages:

```sh
nix profile install github:krezh/kauth#kauth-server github:krezh/kauth#kauth
```

## Run

Export the required configuration:

```sh
export OIDC_ISSUER_URL=https://login.example.com
export OIDC_CLIENT_ID=kauth
export OIDC_CLIENT_SECRET='<client-secret>'
export JWT_SIGNING_KEY="$(openssl rand -base64 32)"
export JWT_ENCRYPTION_KEY="$(openssl rand -base64 32)"
export DATABASE_URL='postgres://kauth:<password>@postgres.example.com:5432/kauth?sslmode=verify-full&sslrootcert=/etc/kauth/postgres-ca.crt'
export BASE_URL=https://kauth.example.com
export CLUSTER_NAME=production
export ADMIN_GROUPS=platform-admins
export KUBECONFIG="$HOME/.kube/config"

kauth-server
```

The database account must be able to create the session and audit tables and
indexes. PostgreSQL is a hard dependency: kauth cannot authenticate requests
while it is unreachable. Kauth must reach PostgreSQL and Kubernetes during
startup.

Terminate public TLS at a reverse proxy, or set `TLS_CERT_FILE` and
`TLS_KEY_FILE` to terminate TLS in kauth.

The dashboard is served at `/`, kauth's control API is under `/api`, and
generated kubeconfigs use `/k8s` on the same hostname.

## Login

```sh
kauth login --url https://kauth.example.com
```

The same browser login opens the dashboard at `https://kauth.example.com/`.
