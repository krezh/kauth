FROM golang:1.25-alpine AS builder

WORKDIR /build

# Build arguments for versioning
ARG VERSION=dev
ARG GIT_COMMIT=unknown
ARG BUILD_DATE

# Copy go mod files
COPY go.mod go.sum ./

# Copy source
COPY . .

# Build with version information
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w \
    -X github.com/krezh/kauth/cmd/kauth/cmd.Version=${VERSION} \
    -X github.com/krezh/kauth/cmd/kauth/cmd.GitCommit=${GIT_COMMIT} \
    -X github.com/krezh/kauth/cmd/kauth/cmd.BuildDate=${BUILD_DATE}" \
    -o kauth-server ./cmd/kauth-server

FROM alpine:latest

# Copy build args to runtime
ARG VERSION=dev
ARG GIT_COMMIT=unknown
ARG BUILD_DATE

# Add labels for metadata
LABEL org.opencontainers.image.title="kauth-server" \
      org.opencontainers.image.description="Kubernetes OIDC authentication server" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${GIT_COMMIT}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.source="https://github.com/krezh/kauth"

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

COPY --from=builder /build/kauth-server .
USER daemon
EXPOSE 8080

CMD ["/app/kauth-server"]
