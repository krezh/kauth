# Quick Start - Using Automated CI/CD

This guide shows you exactly how to use the automated versioning and release system.

## Daily Development Workflow

### 1. Make Your Changes

```bash
# Create a feature branch (or work on main locally)
git checkout -b my-feature

# Make your code changes
vim pkg/auth/handler.go

# Test locally
just test
just build
```

### 2. Commit With Version Control

Your commit message controls the version bump:

```bash
# Patch bump (0.1.0 → 0.1.1) - Bug fixes
git commit -m "fix: resolve authentication timeout issue"

# Minor bump (0.1.0 → 0.2.0) - New features
git commit -m "feat: add SAML authentication support #minor"

# Major bump (0.1.0 → 1.0.0) - Breaking changes
git commit -m "refactor: redesign authentication API #major"

# No version bump - Documentation
git commit -m "docs: update README [skip version]"
```

### 3. Push to Main

```bash
# Option A: Push directly to main (if you have permissions)
git checkout main
git pull
git merge my-feature
git push origin main

# Option B: Create a Pull Request (recommended)
git push origin my-feature
# Create PR on GitHub, get review, merge
```

### 4. Automation Happens Automatically

Once merged to `main`, the CI/CD system:

1. ✅ **Auto-version** runs (~30 seconds)
   - Reads your commit message
   - Creates new tag (e.g., `v0.2.0`)
   - Updates `VERSION` file
   - Commits VERSION back to main

2. ✅ **Build** runs (~2-3 minutes)
   - Builds Docker image with version info
   - Pushes to `ghcr.io/krezh/kauth-server:v0.2.0`
   - Also tags as `latest`

3. ✅ **Release** runs (~1 minute)
   - Generates changelog from commits
   - Publishes Helm chart v0.2.0
   - Creates GitHub Release

**Total time: ~4-5 minutes from merge to release!**

### 5. Use Your Release

```bash
# Pull the Docker image
docker pull ghcr.io/krezh/kauth-server:v0.2.0
docker pull ghcr.io/krezh/kauth-server:latest

# Install with Helm
helm install kauth oci://ghcr.io/krezh/charts/kauth-server --version 0.2.0

# Build with Nix flake (uses VERSION file)
nix build github:krezh/kauth/v0.2.0#kauth-server
```

---

## Common Scenarios

### Scenario 1: Quick Bug Fix

```bash
# Fix the bug
vim pkg/auth/session.go

# Commit and push (automatic patch bump)
git commit -am "fix: prevent session timeout race condition"
git push origin main

# Wait 5 minutes, then:
docker pull ghcr.io/krezh/kauth-server:latest  # Gets v0.1.1
```

### Scenario 2: New Feature

```bash
# Implement feature
vim pkg/auth/oauth.go
vim pkg/auth/oauth_test.go

# Test it
just test

# Commit with minor bump
git commit -am "feat: add GitHub OAuth provider #minor"
git push origin main

# Wait 5 minutes, then:
# New version v0.2.0 is released automatically
```

### Scenario 3: Breaking Change

```bash
# Make breaking API changes
vim pkg/api/v2/handler.go

# Commit with major bump
git commit -am "feat: migrate to v2 API with breaking changes #major"
git push origin main

# Wait 5 minutes, then:
# New version v1.0.0 is released
```

### Scenario 4: Multiple Commits (PR)

```bash
# Your PR has multiple commits:
git log --oneline
# abc123 docs: update examples
# def456 test: add integration tests
# ghi789 feat: add OIDC support

# When PR is merged to main:
# - Auto-version reads the latest commit
# - If "feat:" is in the message → minor bump
# - Creates appropriate version tag
```

### Scenario 5: Documentation Only

```bash
# Update docs (no version bump needed)
vim README.md
git commit -am "docs: add troubleshooting section [skip version]"
git push origin main

# CI/CD skips auto-versioning
# No new release created
```

### Scenario 6: Emergency Hotfix

```bash
# Critical production bug on v1.2.3

# Option A: Fix on main (creates v1.2.4)
git checkout main
git pull
vim pkg/critical/fix.go
git commit -am "fix: critical security issue in token validation"
git push origin main
# → Automatic release v1.2.4

# Option B: Manual release with specific version
just release-manual
# Follow prompts to create specific version
```

---

## Version Bump Reference

| Commit Message Pattern | Bump Type | Example |
|------------------------|-----------|---------|
| `fix: ...` | patch | 0.1.0 → 0.1.1 |
| `feat: ...` | minor | 0.1.0 → 0.2.0 |
| `feat: ... #minor` | minor | 0.1.0 → 0.2.0 |
| `... #major` | major | 0.1.0 → 1.0.0 |
| `BREAKING CHANGE:` | major | 0.1.0 → 1.0.0 |
| `docs: ... [skip version]` | none | No release |
| `chore: ... [skip ci]` | none | No CI run |

---

## Checking Version Information

### Current Version

```bash
# From VERSION file
cat VERSION

# Using justfile
just version

# Output:
# Current version: 0.2.0
# Latest tag: v0.2.0
```

### Release History

```bash
# List all releases
git tag -l "v*"

# Show latest release
git describe --tags --abbrev=0

# View release on GitHub
# Go to: https://github.com/krezh/kauth/releases
```

### Docker Image Tags

```bash
# List available tags
docker pull ghcr.io/krezh/kauth-server:v0.1.0
docker pull ghcr.io/krezh/kauth-server:0.1.0
docker pull ghcr.io/krezh/kauth-server:latest

# Inspect image version
docker inspect ghcr.io/krezh/kauth-server:latest | grep -A5 Labels
```

### Helm Chart Versions

```bash
# Search for versions
helm search repo kauth-server --versions

# Pull specific version
helm pull oci://ghcr.io/krezh/charts/kauth-server --version 0.2.0
```

---

## Troubleshooting

### Version Didn't Bump

**Check 1**: Did commit message have `[skip version]` or `[skip ci]`?
```bash
git log -1
```

**Check 2**: Was commit pushed to main?
```bash
git branch --contains HEAD
```

**Check 3**: Check workflow runs
```bash
# View on GitHub
https://github.com/krezh/kauth/actions
```

### Wrong Version Bump

The auto-version workflow reads commit messages. If you got:
- Expected minor (0.1.0 → 0.2.0) but got patch (0.1.0 → 0.1.1)
  - Add `#minor` to commit message or use `feat:` prefix

**Fix it**:
```bash
# Delete the wrong tag (before it's deployed)
git tag -d v0.1.1
git push origin :refs/tags/v0.1.1

# Create correct tag manually
git tag -a v0.2.0 -m "Release v0.2.0"
git push origin v0.2.0
```

### Need to Rollback a Release

```bash
# Rollback in deployment
helm rollback kauth-server 1

# Or deploy specific old version
helm upgrade kauth-server oci://ghcr.io/krezh/charts/kauth-server --version 0.1.0
docker pull ghcr.io/krezh/kauth-server:v0.1.0
```

### CI/CD Failed

**Check workflow logs**:
1. Go to GitHub Actions
2. Find the failed workflow
3. Check which step failed
4. Common issues:
   - Tests failed → Fix tests
   - Docker build failed → Check Dockerfile
   - Helm package failed → Check Chart.yaml syntax

**Retry**:
- Fix the issue
- Push another commit
- CI/CD will run again

---

## Advanced Usage

### Skipping Workflows

```bash
# Skip both auto-version and CI builds
git commit -m "chore: cleanup [skip ci]"

# Skip only auto-version (but run builds)
git commit -m "chore: update deps [skip version]"
```

### Manual Version Override

```bash
# Use the legacy manual release
just release-manual

# Follow prompts to select:
# 1) patch → v0.1.1
# 2) minor → v0.2.0
# 3) major → v1.0.0
# 4) custom → (enter version)
```

### Checking What Will Happen

```bash
# Before pushing, check your commit message
git log -1 --pretty=%B

# Predict the version bump:
# - Contains "feat:" or "#minor" → minor bump
# - Contains "#major" or "BREAKING CHANGE" → major bump
# - Otherwise → patch bump
# - Contains "[skip version]" → no bump
```

### Working with Nix Flake

```bash
# Local development (uses VERSION file + git SHA)
nix build .#kauth-server
./result/bin/kauth-server --version
# Output: kauth-server version 0.1.0-abc1234

# From GitHub (uses VERSION from that ref)
nix build github:krezh/kauth/v0.2.0#kauth-server
./result/bin/kauth-server --version
# Output: kauth-server version 0.2.0-def5678

# Latest main branch
nix build github:krezh/kauth#kauth-server
```

---

## Summary: The Complete Flow

```
┌─────────────────────────────────────────────────────────────┐
│ 1. Developer makes changes locally                          │
│    • Write code                                              │
│    • Test: just test                                         │
│    • Build: just build                                       │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. Commit with version control                              │
│    git commit -m "feat: new feature #minor"                 │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. Push to main (or merge PR)                               │
│    git push origin main                                      │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. AUTO-VERSION workflow (30 sec)                           │
│    • Creates tag: v0.2.0                                     │
│    • Updates VERSION: 0.2.0                                  │
│    • Commits VERSION [skip ci]                              │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ 5. BUILD workflow (2-3 min)                                 │
│    • Runs tests                                              │
│    • Builds Docker image                                     │
│    • Tags: v0.2.0, 0.2.0, latest                            │
│    • Pushes to ghcr.io                                       │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ 6. RELEASE workflow (1 min)                                 │
│    • Generates changelog                                     │
│    • Packages Helm chart v0.2.0                             │
│    • Pushes Helm to GHCR                                     │
│    • Creates GitHub Release                                  │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ 7. Use the release!                                         │
│    • docker pull ghcr.io/krezh/kauth-server:v0.2.0          │
│    • helm install ... --version 0.2.0                        │
│    • nix build github:krezh/kauth/v0.2.0                    │
└─────────────────────────────────────────────────────────────┘
```

**Total time from commit to release: ~5 minutes**

**Zero manual steps required!** 🎉

---

## Need Help?

- **Full CI/CD docs**: `.github/CICD.md`
- **GitHub Actions**: https://github.com/krezh/kauth/actions
- **Releases**: https://github.com/krezh/kauth/releases
- **Available commands**: `just --list`
