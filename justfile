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

# Create a new release with interactive version selection
release: pre-commit
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
    CURRENT=$(git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0")
    VERSION=${CURRENT#v}
    IFS='.' read -r MAJOR MINOR PATCH <<< "$VERSION"

    # Show current and choose new version
    gum style --foreground 212 --border double --align center --width 50 --padding "1 2" \
        "Current Version" "$CURRENT"

    TYPE=$(gum choose "patch → v$MAJOR.$MINOR.$((PATCH+1))" \
                      "minor → v$MAJOR.$((MINOR+1)).0" \
                      "major → v$((MAJOR+1)).0.0" \
                      "custom")

    case "$TYPE" in
        patch*) NEW="v$MAJOR.$MINOR.$((PATCH+1))" ;;
        minor*) NEW="v$MAJOR.$((MINOR+1)).0" ;;
        major*) NEW="v$((MAJOR+1)).0.0" ;;
        custom) NEW=$(gum input --placeholder "v1.2.3") ;;
    esac

    # Confirm and create
    gum style --foreground 212 --border rounded --align center --width 50 --padding "1 2" \
        "New Release" "$NEW"
    gum confirm "Create release $NEW?" || exit 0

    git tag -a "$NEW" -m "Release $NEW"
    git push origin "$NEW"

    gum style --foreground 212 --border rounded --align center --width 60 --padding "1 2" \
        "✅ Release $NEW created!" "" \
        "🚀 GitHub Actions will build and push" \
        "📦 Check releases on GitHub"

# Clean artifacts
clean:
    rm -rf result result-*
