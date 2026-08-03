# End-to-end tests

The E2E suite builds both kauth binaries and a local container image, creates a
disposable kind cluster, installs the Helm chart, and runs real kubectl requests
through the kauth API proxy. It also deploys ephemeral PostgreSQL and OIDC
provider workloads inside the cluster.

Required tools:

- Docker
- Go
- Helm
- kind
- kubectl

Run the suite from the repository root:

```sh
just test-e2e
```

The suite deletes its cluster and temporary files on completion. Set
`KAUTH_E2E_KEEP_CLUSTER=1` to retain them for debugging; the cluster and artifact
paths are printed when the test exits.

The suite verifies OIDC discovery and token exchange, refresh rotation and replay
rejection, browser callback handling, session activation and SSE delivery,
generated kubeconfigs, exec credentials, malformed credential rejection,
Kubernetes discovery, namespaced CRUD, RBAC denial, reserved-group and
impersonation-header filtering, concurrent requests, watch streaming, exec, logs,
port-forward, shared sessions across replicas, session-keyed audit events, and
immediate session revocation. Dashboard coverage includes browser OIDC login,
PostgreSQL-backed request history and metrics, regular-user ownership isolation,
administrator cross-user visibility, CSRF and pagination defenses, and credential
scrubbing on revocation. Operational coverage includes idempotent migrations,
audit retention, proxy availability and audit recovery during a PostgreSQL outage,
and session continuity across rolling kauth and PostgreSQL restarts.
