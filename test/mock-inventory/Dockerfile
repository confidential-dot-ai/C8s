# Bump: crane digest golang:1.27.3
FROM golang:1.27.3@sha256:f24164268fc1e741bbdc0066dbadcf1c8426c5a8489f0729c02c3905a53032fd AS builder

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
FROM busybox:1.38@sha256:fd7dc98638c8e305f4dc34e979f1c0fdfdcaeb0fbf8fcff77ae834b6da3d7e6e
COPY --from=builder /mock-inventory /mock-inventory
ENTRYPOINT ["/mock-inventory"]
