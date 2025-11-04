FROM golang:1.25-alpine AS builder

WORKDIR /build

# Build arguments for version info
ARG VERSION="dev"
ARG GIT_COMMIT="unknown"

# Copy go mod files
COPY go.mod go.sum ./

# Copy source
COPY . .

# Build with version information
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X github.com/krezh/kauth/cmd/kauth/cmd.Version=${VERSION} -X github.com/krezh/kauth/cmd/kauth/cmd.GitCommit=${GIT_COMMIT}" \
    -o kauth-server ./cmd/kauth-server

FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

COPY --from=builder /build/kauth-server .
USER daemon
EXPOSE 8080

CMD ["/app/kauth-server"]
