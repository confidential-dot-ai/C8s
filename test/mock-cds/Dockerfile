# Bump: crane digest golang:1.26
FROM golang:1.27@sha256:3680233e3204827fbdc66088528ae6d4b3d034f51d03a99d454f6de034888244 AS builder

WORKDIR /src
# Repo-root build context (the module replaces c8s => ../..); #13's .dockerignore must keep these paths.
COPY go.mod go.sum ./
COPY pkg/ ./pkg/
COPY test/mock-cds/ ./test/mock-cds/
RUN CGO_ENABLED=0 go build -C test/mock-cds -ldflags="-s -w" -o /mock-cds .

# Bump: crane digest gcr.io/distroless/static-debian12:latest
FROM gcr.io/distroless/static-debian12:latest@sha256:d75cdd72874d4790092fcb1b058493ecf6bb5bf2b2b897045b00ff01d91843f2
COPY --from=builder /mock-cds /mock-cds
ENTRYPOINT ["/mock-cds"]
