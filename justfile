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

# Run tests with coverage
coverage:
    go test -coverprofile=coverage.out ./...
    go tool cover -html=coverage.out -o coverage.html

fmt:
    go fmt ./...

lint:
    golangci-lint run --tests=false

vet:
    go vet ./...

build:
    go build ./cmd/kauth
    go build ./cmd/kauth-server

# Build docker image for kauth-server
docker-build: build
    docker build -t ghcr.io/krezh/kauth-server:latest .

# Validate Helm chart
helm-lint:
    helm lint helm/

# Format, vet, test, lint
check: fmt vet test lint

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
