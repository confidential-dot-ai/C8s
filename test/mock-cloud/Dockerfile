# Bump: crane digest golang:1.27.3
FROM golang:1.27.3@sha256:e519d3b0a5b285e5aa53ab9eef02bc6bbb9cb04608389b743a136a9ce75f0d1e AS builder

WORKDIR /src
# Repo-root build context, as the other mocks; the module imports nothing of c8s.
COPY test/mock-cloud/ ./test/mock-cloud/
RUN CGO_ENABLED=0 go build -C test/mock-cloud -ldflags="-s -w" -o /mock-cloud .

# Bump: crane digest gcr.io/distroless/static-debian12:latest
FROM gcr.io/distroless/static-debian12:latest@sha256:d75cdd72874d4790092fcb1b058493ecf6bb5bf2b2b897045b00ff01d91843f2
COPY --from=builder /mock-cloud /mock-cloud
ENTRYPOINT ["/mock-cloud"]
