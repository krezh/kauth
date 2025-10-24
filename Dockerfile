FROM golang:1.25-alpine AS builder

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./

# Copy source
COPY . .

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -o kauth-server ./cmd/kauth-server

FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /app

COPY --from=builder /build/kauth-server .
USER daemon
EXPOSE 8080

CMD ["/app/kauth-server"]
