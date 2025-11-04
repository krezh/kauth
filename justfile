# kauth justfile

# Show available commands
default:
    @just --list

# Run tests
test:
    go test ./...

fmt:
    go fmt ./...

lint:
    golangci-lint run --tests=false

vet:
    go vet ./...

build:
    go build ./cmd/kauth
    go build ./cmd/kauth-server

# Format and lint
check: fmt test lint

# Update flake
update:
    nix flake update

flake-build:
    nix build .#kauth
    nix build .#kauth-server

# Update vendor hashes in flake.nix
vendor:
    #!/usr/bin/env bash
    gomod2nix

pre-commit: update vet vendor check flake-build

# Note: Releases are now automated via CI/CD
# When you push to main, a new version tag is automatically created
# To control the version bump, use conventional commits:
#   - fix: ... → patch bump (v1.0.0 → v1.0.1)
#   - feat: ... → minor bump (v1.0.0 → v1.1.0)
#   - BREAKING CHANGE: ... → major bump (v1.0.0 → v2.0.0)
#
# To manually create a release with interactive version selection (legacy):
release-manual: pre-commit
    #!/usr/bin/env bash
    set -e

    # Ensure we're on main
    BRANCH=$(git branch --show-current)
    if [[ "$BRANCH" != "main" ]]; then
        echo "❌ Must be on main branch to release (currently on: $BRANCH)"
        exit 1
    fi

    # Sync with remote
    git pull
    git push

    # Get current version
    CURRENT=$(git describe --tags --abbrev=0 2>/dev/null || echo "v0.1.0")
    VERSION=${CURRENT#v}
    IFS='.' read -r MAJOR MINOR PATCH <<< "$VERSION"

    echo "Current Version: $CURRENT"
    echo ""
    echo "Choose version bump:"
    echo "1) patch → v$MAJOR.$MINOR.$((PATCH+1))"
    echo "2) minor → v$MAJOR.$((MINOR+1)).0"
    echo "3) major → v$((MAJOR+1)).0.0"
    echo "4) custom"
    read -p "Enter choice [1-4]: " CHOICE

    case "$CHOICE" in
        1) NEW="v$MAJOR.$MINOR.$((PATCH+1))" ;;
        2) NEW="v$MAJOR.$((MINOR+1)).0" ;;
        3) NEW="v$((MAJOR+1)).0.0" ;;
        4) read -p "Enter version (e.g., v1.2.3): " NEW ;;
        *) echo "Invalid choice"; exit 1 ;;
    esac

    echo ""
    echo "Creating release: $NEW"
    read -p "Continue? [y/N]: " CONFIRM
    if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
        echo "Cancelled"
        exit 0
    fi

    git tag -a "$NEW" -m "Release $NEW"
    git push origin "$NEW"

    echo ""
    echo "✅ Release $NEW created!"
    echo "🚀 GitHub Actions will build and push"
    echo "📦 Check releases on GitHub"

# Clean artifacts
clean:
    rm -rf result result-*
