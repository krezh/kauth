# CI/CD Automation Guide

This repository uses fully automated CI/CD pipelines for versioning, building, and releasing.

## Overview

The CI/CD system consists of three main workflows:

1. **Auto Version** (`auto-version.yaml`) - Automatically creates version tags and updates VERSION file
2. **Build and Push** (`build.yaml`) - Builds and pushes Docker images with version info
3. **Release** (`release.yaml`) - Creates GitHub releases and publishes Helm charts
4. **Update Flake** (`update-flake.yaml`) - Keeps Nix dependencies in sync

## Version Management

### VERSION File

The repository uses a `VERSION` file as the single source of truth for semantic versioning:

- **Location**: `/VERSION` (root of repository)
- **Format**: Plain text, semantic version without 'v' prefix (e.g., `1.2.3`)
- **Updated**: Automatically by CI/CD after creating a new git tag
- **Used by**: Nix flake, Docker builds, Helm charts

Check current version:
```bash
just version
# or
cat VERSION
```

## Automated Versioning

### How It Works

When you push to the `main` branch:

1. The **Auto Version** workflow automatically analyzes your commits
2. It determines the next version number based on commit message markers
3. It creates and pushes a new git tag (e.g., `v1.2.3`)
4. It updates the `VERSION` file and commits it back to `main`
5. The tag triggers the **Build** and **Release** workflows
6. All artifacts (Docker, Helm, Flake) use the same semantic version

### Version Bump Rules

The version bump follows these patterns:

- **Default**: `patch` bump (v1.0.0 → v1.0.1)
- **With `#major` in commit**: Major bump (v1.0.0 → v2.0.0)
- **With `#minor` in commit**: Minor bump (v1.0.0 → v1.1.0)
- **With `#patch` in commit**: Patch bump (v1.0.0 → v1.0.1)

### Example Commit Messages

```bash
# Patch bump (default)
git commit -m "fix: resolve authentication issue"

# Minor bump
git commit -m "feat: add new OAuth provider support #minor"

# Major bump
git commit -m "refactor: complete API redesign #major"

# Skip versioning
git commit -m "docs: update README [skip version]"
```

### Skipping Auto-Versioning

To skip automatic versioning, include one of these in your commit message:
- `[skip ci]`
- `[skip version]`

## Build Pipeline

The **Build and Push** workflow (`build.yaml`) runs on:
- Push to `main` branch
- New tags (`v*`)
- Pull requests (build only, no push)

### What It Does

1. Runs Go tests
2. Builds Docker image with proper version information
3. Pushes to GitHub Container Registry (`ghcr.io`)
4. Tags images appropriately:
   - `main` branch → `latest` tag
   - Version tags → `v1.2.3` and `1.2.3` tags
   - PRs → `pr-<number>` tag

### Version Information

The build pipeline automatically injects version information:
- **VERSION**: Git tag (e.g., `v1.2.3`) or commit SHA
- **GIT_COMMIT**: Full commit SHA
- **BUILD_DATE**: ISO 8601 timestamp

This information is embedded in:
- Go binaries (via `-ldflags`)
- Docker image labels (OCI format)

## Release Pipeline

The **Release** workflow (`release.yaml`) runs when a version tag is pushed.

### What It Does

1. Generates a changelog from commits since the last tag
2. Packages the Helm chart with the new version
3. Pushes Helm chart to GitHub Container Registry
4. Creates a GitHub Release with:
   - Generated changelog
   - Container image pull commands
   - Helm install commands

## Flake Versioning

The Nix flake (`flake.nix`) reads version from the VERSION file:

- **Source**: Reads from `/VERSION` file via `builtins.readFile`
- **Development builds**: Appends `-<shortRev>` suffix (e.g., `1.2.3-abc1234`)
- **Dirty builds**: Appends `-dirty` suffix when working directory has changes
- **Version info**: Injected into binaries via `-ldflags`

Build the flake:
```bash
# Build from local checkout
nix build .#kauth
nix build .#kauth-server

# Build from GitHub (uses VERSION from that ref)
nix build github:krezh/kauth#kauth
nix build github:krezh/kauth/v1.2.3#kauth

# Check version in built binary
./result/bin/kauth-server --version
```

The flake will always use the VERSION file content, ensuring consistency across:
- Local development builds
- CI/CD builds
- GitHub Flake registry builds
- Nix binary cache

## Manual Releases (Legacy)

While releases are now automated, you can still create manual releases:

```bash
# Using justfile (no longer requires gum)
just release-manual
```

This is useful for:
- Creating hotfix releases
- Bumping to a specific version
- Testing the release process locally

## Workflow Triggers Summary

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| Auto Version | Push to `main` | Create version tags automatically |
| Build & Push | Push to `main`, tags `v*`, PRs | Build and publish Docker images |
| Release | Tags `v*` | Create GitHub releases and publish Helm |
| Update Flake | Changes to `go.mod`/`go.sum` | Keep Nix dependencies in sync |

## Best Practices

1. **Use descriptive commit messages** - They become your changelog
2. **Merge PRs to main** - Don't push directly to main
3. **Use conventional commits** - For better changelogs (optional)
4. **Review automated releases** - Check GitHub releases after merging
5. **Test in PRs** - Docker images are built for every PR

## Troubleshooting

### Version not bumped after merge
- Check if commit message contains `[skip ci]` or `[skip version]`
- Verify the commit was pushed to `main` branch
- Check workflow runs in GitHub Actions

### Build failed
- Check test results - builds fail if tests fail
- Verify `go.mod` and `go.sum` are in sync
- Check for syntax errors in Dockerfile

### Release not created
- Ensure a version tag exists (check git tags)
- Verify `release.yaml` workflow completed successfully
- Check GitHub Actions logs for errors

## Container Images

Pull the latest image:
```bash
docker pull ghcr.io/krezh/kauth-server:latest
docker pull ghcr.io/krezh/kauth-server:v1.2.3
```

## Helm Charts

Install the Helm chart:
```bash
helm install kauth-server oci://ghcr.io/krezh/charts/kauth-server --version 1.2.3
```

## Development Workflow

Standard workflow for contributors:

1. Create a feature branch
2. Make your changes
3. Push and create a PR
4. Wait for CI checks (build & test)
5. Merge to `main` (after approval)
6. Auto-versioning creates a tag
7. Release is automatically published

No manual intervention needed! 🎉
