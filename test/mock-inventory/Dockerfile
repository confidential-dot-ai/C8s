# Bump: crane digest golang:1.27
FROM golang:1.27@sha256:3680233e3204827fbdc66088528ae6d4b3d034f51d03a99d454f6de034888244 AS builder

WORKDIR /src
# Repo-root build context (the module replaces c8s => ../..); #13's .dockerignore must keep these paths.
COPY go.mod go.sum ./
COPY pkg/ ./pkg/
COPY test/mock-inventory/ ./test/mock-inventory/
RUN CGO_ENABLED=0 go build -C test/mock-inventory -ldflags="-s -w" -o /mock-inventory .

# busybox rather than the sibling mocks' distroless: the lane's readiness probe
# is `test -S` on the inventory socket.
# Bump: crane digest busybox:1.37
FROM busybox:1.37@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e
COPY --from=builder /mock-inventory /mock-inventory
ENTRYPOINT ["/mock-inventory"]
