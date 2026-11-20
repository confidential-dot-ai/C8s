# Bump: crane digest golang:1.27.3
FROM golang:1.27.4@sha256:205c7636d74e0ffbe3d007162df7d74f859f5a8c8322dfb9f907977686c126cf AS builder

WORKDIR /src
# Repo-root build context, as the other mocks; the module imports nothing of c8s.
COPY test/mock-cloud/ ./test/mock-cloud/
RUN CGO_ENABLED=0 go build -C test/mock-cloud -ldflags="-s -w" -o /mock-cloud .

# Bump: crane digest gcr.io/distroless/static-debian12:latest
FROM gcr.io/distroless/static-debian12:latest@sha256:d75cdd72874d4790092fcb1b058493ecf6bb5bf2b2b897045b00ff01d91843f2
COPY --from=builder /mock-cloud /mock-cloud
ENTRYPOINT ["/mock-cloud"]
