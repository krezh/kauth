# kauth justfile

# Show available commands
default:
    @just --list

# Run tests
test:
    go test ./...

# Format and lint
check:
    go fmt ./...
    golangci-lint run

# Update flake
update:
    nix flake update

flake-build:
    nix build .#kauth
    nix build .#kauth-server

# Update vendor hashes in flake.nix
vendor:
    #!/usr/bin/env bash
    echo "Getting vendor hash for kauth..."
    kauth_hash=$(nix build .#kauth 2>&1 | grep -oP 'got:\s+\K\S+' || echo "")

    echo "Getting vendor hash for kauth-server..."
    server_hash=$(nix build .#kauth-server 2>&1 | grep -oP 'got:\s+\K\S+' || echo "")

    if [ -n "$kauth_hash" ]; then
        sed -i "0,/vendorHash = \".*\";/{s|vendorHash = \".*\";|vendorHash = \"$kauth_hash\";|}" flake.nix
        echo "Updated kauth vendorHash to: $kauth_hash"
    fi

    if [ -n "$server_hash" ]; then
        sed -i "0,/vendorHash = \".*\";/! {0,/vendorHash = \".*\";/ s|vendorHash = \".*\";|vendorHash = \"$server_hash\";|}" flake.nix
        echo "Updated kauth-server vendorHash to: $server_hash"
    fi

    if [ -z "$kauth_hash" ] && [ -z "$server_hash" ]; then
        echo "No hash mismatch found - vendorHashes may already be correct"
    fi

# Tag current commit with version
pre-commit: vendor test check flake-build

# Create a new release with interactive version selection
release:
    #!/usr/bin/env bash
    set -e

    # Check if gum is installed
    if ! command -v gum &> /dev/null; then
        echo "gum is not installed"
        echo "Install with: nix profile install nixpkgs#gum"
        exit 1
    fi

    # Check for uncommitted changes
    if ! git diff-index --quiet HEAD --; then
        gum style \
            --foreground 196 --border-foreground 196 --border rounded \
            --align center --width 50 --margin "1 2" --padding "1 2" \
            "⚠️  Uncommitted changes detected" \
            "" \
            "Please commit or stash your changes first"
        exit 1
    fi

    # Pull latest changes and tags (if on main/master)
    CURRENT_BRANCH=$(git branch --show-current)
    if [[ "$CURRENT_BRANCH" == "main" ]] || [[ "$CURRENT_BRANCH" == "master" ]]; then
        gum spin --spinner dot --title "Syncing with remote..." -- \
            git pull --ff-only --tags origin "$CURRENT_BRANCH" || {
                gum style \
                    --foreground 196 --border-foreground 196 --border rounded \
                    --align center --width 50 --margin "1 2" --padding "1 2" \
                    "⚠️  Cannot pull cleanly" \
                    "" \
                    "Please resolve conflicts or rebase first"
                exit 1
            }
    else
        # Just fetch tags if not on main/master
        gum spin --spinner dot --title "Fetching tags..." -- \
            git fetch --tags origin
    fi

    # Get current version
    CURRENT_VERSION=$(git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0")

    # Parse version
    VERSION=${CURRENT_VERSION#v}
    IFS='.' read -r -a VERSION_PARTS <<< "$VERSION"
    MAJOR="${VERSION_PARTS[0]}"
    MINOR="${VERSION_PARTS[1]}"
    PATCH="${VERSION_PARTS[2]}"

    # Show current version
    gum style \
        --foreground 212 --border-foreground 212 --border double \
        --align center --width 50 --margin "1 2" --padding "1 2" \
        "Current Version" "$CURRENT_VERSION"

    # Choose release type
    RELEASE_TYPE=$(gum choose \
        "patch  → v$MAJOR.$MINOR.$((PATCH+1))" \
        "minor  → v$MAJOR.$((MINOR+1)).0" \
        "major  → v$((MAJOR+1)).0.0" \
        "custom → enter version manually")

    # Calculate new version
    case "$RELEASE_TYPE" in
        patch*)
            NEW_VERSION="v$MAJOR.$MINOR.$((PATCH+1))"
            ;;
        minor*)
            NEW_VERSION="v$MAJOR.$((MINOR+1)).0"
            ;;
        major*)
            NEW_VERSION="v$((MAJOR+1)).0.0"
            ;;
        custom*)
            NEW_VERSION=$(gum input --placeholder "v1.2.3" --prompt "New version: ")
            ;;
    esac

    # Show what will happen
    gum style \
        --foreground 212 --border-foreground 212 --border rounded \
        --align center --width 50 --margin "1 2" --padding "1 2" \
        "New Release" "$NEW_VERSION"

    # Confirm
    gum confirm "Create release $NEW_VERSION?" || exit 0

    # Create and push tag
    gum spin --spinner dot --title "Creating tag..." -- \
        git tag -a "$NEW_VERSION" -m "Release $NEW_VERSION"

    gum spin --spinner dot --title "Pushing tag..." -- \
        git push origin "$NEW_VERSION"

    # Success message
    gum style \
        --foreground 212 --border-foreground 212 --border rounded \
        --align center --width 60 --margin "1 2" --padding "1 2" \
        "✅ Release $NEW_VERSION created!" \
        "" \
        "🚀 GitHub Actions will build and push Docker image" \
        "📦 https://github.com/$(git config --get remote.origin.url | sed 's/.*github.com[:/]\(.*\)\.git/\1/')/releases"

# Clean artifacts
clean:
    rm -rf result result-*
