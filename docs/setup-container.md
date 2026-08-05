# Container setup

Use the container when kauth runs outside Kubernetes or under a scheduler other
than Helm. The container needs a kubeconfig for the cluster it proxies.

## Prerequisites

- A PostgreSQL database
- An OIDC client
- A public HTTPS endpoint for port 8080
- A kubeconfig readable inside the container

The kubeconfig identity needs cluster-scoped `impersonate` access to core
`users` and `groups`.

Register this OIDC redirect URI:

```text
https://kauth.example.com/callback
```

## Run

Create an environment file:

```dotenv
OIDC_ISSUER_URL=https://login.example.com
OIDC_CLIENT_ID=kauth
OIDC_CLIENT_SECRET=<client-secret>
JWT_SIGNING_KEY=<base64-encoded-32-byte-key>
JWT_ENCRYPTION_KEY=<base64-encoded-32-byte-key>
DATABASE_URL=postgres://kauth:<password>@postgres.example.com:5432/kauth?sslmode=verify-full&sslrootcert=/certs/postgres-ca.crt
BASE_URL=https://kauth.example.com
CLUSTER_NAME=production
ADMIN_GROUPS=platform-admins
KUBECONFIG=/config/kubeconfig
```

Run the image, mounting the kubeconfig and PostgreSQL CA certificate read-only:

```sh
docker run --rm \
  --env-file kauth.env \
  --publish 8080:8080 \
  --volume "$HOME/.kube/config:/config/kubeconfig:ro" \
  --volume "$PWD/postgres-ca.crt:/certs/postgres-ca.crt:ro" \
  ghcr.io/krezh/kauth-server:latest
```

The database account must be able to create the session and audit tables and
indexes. PostgreSQL is a hard dependency: kauth cannot authenticate requests
while it is unreachable.

Terminate public TLS at a reverse proxy or gateway in front of port 8080. To
terminate TLS in kauth instead, mount the certificate and key and set
`TLS_CERT_FILE` and `TLS_KEY_FILE`.

The dashboard is served at `/`, kauth's control API is under `/api`, and
generated kubeconfigs use `/k8s` on the same hostname.

## Login

```sh
kauth login --url https://kauth.example.com
```

The same browser login opens the dashboard at `https://kauth.example.com/`.
