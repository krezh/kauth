# kauth justfile

# Show available commands
default:
    @just --list

# Run go mod tidy
tidy:
    go mod tidy
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

vendor:
    govendor

pre-commit: update tidy vet vendor check flake-build

# Clean artifacts
clean:
    rm -rf result result-*
