# Bump: crane digest golang:1.27.3
FROM golang:1.27.3@sha256:2920bb124f1a2e12a1d39f0cab756ae0068441ee1da7655dec7f5e374944095b AS builder

WORKDIR /src
# Repo-root build context (the module replaces c8s => ../..); #13's .dockerignore must keep these paths.
COPY go.mod go.sum ./
COPY pkg/ ./pkg/
COPY internal/strictjson/ ./internal/strictjson/
COPY test/mock-inventory/ ./test/mock-inventory/
RUN CGO_ENABLED=0 go build -C test/mock-inventory -ldflags="-s -w" -o /mock-inventory .

# busybox rather than the sibling mocks' distroless: the lane's readiness probe
# is `test -S` on the inventory socket.
# Bump: crane digest busybox:1.37
FROM busybox:1.38@sha256:a46257e06c82ad85242d0d38077d0a52d9896389ca60a1a59d3463db586e5fa4
COPY --from=builder /mock-inventory /mock-inventory
ENTRYPOINT ["/mock-inventory"]
