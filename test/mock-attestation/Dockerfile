# Bump: crane digest golang:1.27.3
FROM golang:1.27.3@sha256:e519d3b0a5b285e5aa53ab9eef02bc6bbb9cb04608389b743a136a9ce75f0d1e AS builder

WORKDIR /src
# Repo-root build context (the module replaces c8s => ../..); #13's .dockerignore must keep these paths.
COPY go.mod go.sum ./
COPY pkg/ ./pkg/
COPY test/mock-attestation/ ./test/mock-attestation/
RUN CGO_ENABLED=0 go build -C test/mock-attestation -ldflags="-s -w" -o /mock-attestation .

# Bump: crane digest gcr.io/distroless/static-debian12:latest
FROM gcr.io/distroless/static-debian12:latest@sha256:d75cdd72874d4790092fcb1b058493ecf6bb5bf2b2b897045b00ff01d91843f2
# The cloud chart runs the attestation-api image as /attestation-api.
COPY --from=builder /mock-attestation /attestation-api
ENTRYPOINT ["/attestation-api"]
