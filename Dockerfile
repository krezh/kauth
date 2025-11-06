FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

# Copy the pre-built binary from GoReleaser
COPY kauth-server .

USER daemon
EXPOSE 8080

CMD ["/app/kauth-server"]
