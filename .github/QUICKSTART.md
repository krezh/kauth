# Quick Start - Using CI/CD

This guide shows you exactly how to use the versioning and release system.

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

### 2. Commit Normally (No Release)

**Most commits don't need a release:**

```bash
# Regular commits - NO release created
git commit -m "fix: resolve authentication timeout issue"
git commit -m "feat: add SAML authentication support"
git commit -m "refactor: improve error handling"
git commit -m "test: add integration tests"

# Push to main - CI runs tests, but NO release
git push origin main
```

### 3. Create a Release When Ready

**Option A: Add `[release]` to commit message**

```bash
# Patch bump (0.1.0 → 0.1.1)
git commit -m "fix: resolve critical auth bug [release]"

# Minor bump (0.1.0 → 0.2.0)
git commit -m "feat: add OAuth support [release] #minor"

# Major bump (0.1.0 → 1.0.0)
git commit -m "breaking: new API [release] #major"

git push origin main
# → Release created automatically!
```

**Option B: Manual release from GitHub**

```bash
# Push your commits normally
git push origin main

# Then go to GitHub:
# Actions → Auto Version and Release → Run workflow
# Select: patch/minor/major
# → Release created!
```

**Option C: Use justfile (local)**

```bash
just release-manual
# Follow prompts to create release
```

### 4. What Happens Next

**Without `[release]` in commit:**
- ✅ CI runs tests and builds
- ✅ Docker image pushed with commit SHA
- ❌ NO version tag created
- ❌ NO GitHub Release created

**With `[release]` in commit or manual trigger:**
1. ✅ **Auto-version** runs (~30 seconds)
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

**Total time: ~4-5 minutes from trigger to release!**

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

### Scenario 1: Quick Bug Fix (No Release)

```bash
# Fix the bug
vim pkg/auth/session.go

# Commit and push - NO release
git commit -am "fix: prevent session timeout race condition"
git push origin main

# CI runs tests, but no version created
# No release needed yet
```

### Scenario 2: Release a Bug Fix

```bash
# After accumulating several bug fixes
git commit -am "fix: critical security issue [release]"
git push origin main

# Wait 5 minutes, then:
docker pull ghcr.io/krezh/kauth-server:latest  # Gets v0.1.1
```

### Scenario 3: Accumulate Changes, Then Release

```bash
# Work on feature over multiple commits
git commit -am "feat: add OAuth scaffold"
git commit -am "feat: implement OAuth flow"
git commit -am "test: add OAuth tests"
git commit -am "docs: document OAuth setup"
git push origin main

# Later, when ready to release:
git commit -am "feat: OAuth provider ready [release] #minor" --allow-empty
git push origin main

# OR use GitHub Actions UI to manually trigger release
```

### Scenario 4: Breaking Change Release

```bash
# Make breaking API changes
vim pkg/api/v2/handler.go

# When ready to release
git commit -am "feat: v2 API ready [release] #major"
git push origin main

# Wait 5 minutes, then:
# New version v1.0.0 is released
```

### Scenario 5: Multiple Commits in PR

```bash
# Your PR has multiple commits:
git log --oneline
# abc123 docs: update examples
# def456 test: add integration tests
# ghi789 feat: add OIDC support

# Merge PR normally - NO release
git push origin main

# Later, add release commit:
git commit -am "release: OIDC support ready [release] #minor" --allow-empty
git push origin main
```

### Scenario 6: Just Want to Merge, No Release

```bash
# This is the DEFAULT behavior
git commit -am "feat: work in progress feature"
git commit -am "fix: small bug"
git commit -am "docs: update README"
git push origin main

# Everything merges, CI runs, but NO releases created
# Release only happens when YOU decide
```

### Scenario 7: Emergency Hotfix

```bash
# Critical production bug on v1.2.3

# Fix it
git checkout main
git pull
vim pkg/critical/fix.go

# Release immediately
git commit -am "fix: critical security issue [release]"
git push origin main
# → Automatic release v1.2.4

# OR use GitHub Actions UI for immediate manual release
```

---

## Version Bump Reference

**Key Point: Releases only happen when you add `[release]` or manually trigger!**

| Commit Message | Release? | Bump Type | Example |
|----------------|----------|-----------|---------|
| `fix: something` | ❌ NO | - | Just merges |
| `fix: something [release]` | ✅ YES | patch | 0.1.0 → 0.1.1 |
| `feat: new thing [release]` | ✅ YES | patch | 0.1.0 → 0.1.1 |
| `feat: new thing [release] #minor` | ✅ YES | minor | 0.1.0 → 0.2.0 |
| `anything [release] #major` | ✅ YES | major | 0.1.0 → 1.0.0 |
| `docs: update` | ❌ NO | - | Just merges |

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

# Will it trigger a release?
# - Contains "[release]" → YES, creates release
# - Otherwise → NO, just merges

# If [release] is present, what bump?
# - Contains "#major" → major bump (1.0.0)
# - Contains "#minor" → minor bump (0.2.0)
# - Otherwise → patch bump (0.1.1)
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

### Regular Development (No Release)

```
┌──────────────────────────────────────────┐
│ 1. Make changes                          │
│    git commit -m "feat: new feature"     │
│    git push origin main                  │
└────────────────┬─────────────────────────┘
                 │
                 ▼
┌──────────────────────────────────────────┐
│ 2. CI runs                               │
│    • Tests pass ✅                       │
│    • Builds succeed ✅                   │
│    • NO release created ❌               │
└──────────────────────────────────────────┘

Developer continues working...
```

### When Ready to Release

```
┌─────────────────────────────────────────────────────────────┐
│ 1. Decide to release                                        │
│    git commit -m "release: ready [release] #minor"          │
│    OR use GitHub Actions UI                                  │
│    git push origin main                                      │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. AUTO-VERSION workflow (30 sec)                           │
│    • Creates tag: v0.2.0                                     │
│    • Updates VERSION: 0.2.0                                  │
│    • Commits VERSION [skip ci]                              │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. BUILD workflow (2-3 min)                                 │
│    • Runs tests                                              │
│    • Builds Docker image                                     │
│    • Tags: v0.2.0, 0.2.0, latest                            │
│    • Pushes to ghcr.io                                       │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. RELEASE workflow (1 min)                                 │
│    • Generates changelog                                     │
│    • Packages Helm chart v0.2.0                             │
│    • Pushes Helm to GHCR                                     │
│    • Creates GitHub Release                                  │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ 5. Use the release!                                         │
│    • docker pull ghcr.io/krezh/kauth-server:v0.2.0          │
│    • helm install ... --version 0.2.0                        │
│    • nix build github:krezh/kauth/v0.2.0                    │
└─────────────────────────────────────────────────────────────┘
```

**Release only when YOU trigger it!**
**Total time from trigger to release: ~5 minutes** 🎉

---

## Need Help?

- **Full CI/CD docs**: `.github/CICD.md`
- **GitHub Actions**: https://github.com/krezh/kauth/actions
- **Releases**: https://github.com/krezh/kauth/releases
- **Available commands**: `just --list`
