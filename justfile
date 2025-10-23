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
tag VERSION: vendor test check
    @echo "Tagging version {{ VERSION }}..."
    git tag -a {{ VERSION }} -m "Release {{ VERSION }}"
    git push origin {{ VERSION }}
    @echo "Tagged and pushed {{ VERSION }}"

# Clean artifacts
clean:
    rm -rf result result-*
