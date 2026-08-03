# Helm setup

Use Helm when kauth runs inside the Kubernetes cluster it proxies.

## Prerequisites

- A PostgreSQL database
- An OIDC client
- A public HTTPS hostname for kauth
- Helm and kubectl access to the cluster

Register this OIDC redirect URI:

```text
https://kauth.example.com/callback
```

## Install

Create the namespace and configuration Secret:

```sh
kubectl create namespace kauth
kubectl --namespace kauth create secret generic kauth-config \
  --from-literal=OIDC_ISSUER_URL=https://login.example.com \
  --from-literal=OIDC_CLIENT_ID=kauth \
  --from-literal=OIDC_CLIENT_SECRET='<client-secret>' \
  --from-literal=JWT_SIGNING_KEY="$(openssl rand -base64 32)" \
  --from-literal=JWT_ENCRYPTION_KEY="$(openssl rand -base64 32)" \
  --from-literal=DATABASE_URL='postgres://kauth:<password>@postgres.example.com:5432/kauth?sslmode=verify-full'
```

Create `kauth-values.yaml`:

```yaml
env:
  - name: BASE_URL
    value: https://kauth.example.com
  - name: CLUSTER_NAME
    value: production
  - name: ADMIN_GROUPS
    value: platform-admins

envFrom:
  - secretRef:
      name: kauth-config

httpRoute:
  enabled: true
  hostnames:
    - kauth.example.com
```

Use the TLS parameters required by your PostgreSQL provider. If it uses a
private CA, provide a custom image containing that CA and reference it with the
`sslrootcert` URL parameter.

Install the chart:

```sh
helm install kauth oci://ghcr.io/krezh/charts/kauth-server \
  --namespace kauth \
  --values kauth-values.yaml
```

The chart installs the OAuthSession CRD, service account, namespaced session
permissions, and cluster-scoped user/group impersonation permissions.

The dashboard is served at `https://kauth.example.com/`, kauth's control API is
under `/api`, and generated kubeconfigs use `https://kauth.example.com/k8s`.

## Upgrade

Helm does not update CRDs stored in a chart's `crds/` directory. Apply the CRD
from the new release before upgrading:

```sh
kubectl apply --server-side \
  -f https://raw.githubusercontent.com/krezh/kauth/v<VERSION>/helm/crds/oauthsession.yaml
helm upgrade kauth oci://ghcr.io/krezh/charts/kauth-server \
  --namespace kauth \
  --version <VERSION> \
  --values kauth-values.yaml
```

Users upgrading from webhook credentials must log in again.

## Login

```sh
kauth login --url https://kauth.example.com
```

The same browser login opens the dashboard at `https://kauth.example.com/`.
