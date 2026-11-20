# Bump: crane digest golang:1.27.3
FROM golang:1.27.4@sha256:205c7636d74e0ffbe3d007162df7d74f859f5a8c8322dfb9f907977686c126cf AS builder

WORKDIR /src
# Repo-root build context (the module replaces c8s => ../..); #13's .dockerignore must keep these paths.
COPY go.mod go.sum ./
COPY pkg/ ./pkg/
COPY internal/readutil/ ./internal/readutil/
COPY internal/strictjson/ ./internal/strictjson/
COPY test/mock-inventory/ ./test/mock-inventory/
RUN CGO_ENABLED=0 go build -C test/mock-inventory -ldflags="-s -w" -o /mock-inventory .

# busybox rather than the sibling mocks' distroless: the lane's readiness probe
# is `test -S` on the inventory socket.
# Bump: crane digest busybox:1.37
FROM busybox:1.38@sha256:a46257e06c82ad85242d0d38077d0a52d9896389ca60a1a59d3463db586e5fa4
COPY --from=builder /mock-inventory /mock-inventory
ENTRYPOINT ["/mock-inventory"]
