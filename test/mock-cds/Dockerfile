# Bump: crane digest golang:1.27.3
FROM golang:1.27.3@sha256:2920bb124f1a2e12a1d39f0cab756ae0068441ee1da7655dec7f5e374944095b AS builder

WORKDIR /src
# Repo-root build context (the module replaces c8s => ../..); #13's .dockerignore must keep these paths.
COPY go.mod go.sum ./
COPY pkg/ ./pkg/
COPY internal/strictjson/ ./internal/strictjson/
COPY test/mock-cds/ ./test/mock-cds/
RUN CGO_ENABLED=0 go build -C test/mock-cds -ldflags="-s -w" -o /mock-cds .

# Bump: crane digest gcr.io/distroless/static-debian12:latest
FROM gcr.io/distroless/static-debian12:latest@sha256:d75cdd72874d4790092fcb1b058493ecf6bb5bf2b2b897045b00ff01d91843f2
COPY --from=builder /mock-cds /mock-cds
ENTRYPOINT ["/mock-cds"]
