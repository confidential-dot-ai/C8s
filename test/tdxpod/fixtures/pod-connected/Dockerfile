# The connected acceptance workload image (podfixture.Image): pod-netcheck,
# built from netcheck/ beside this file, in a distroless image, so a pod
# document pins one digest and one argv per mode. Repo-root build context;
# the program needs only this directory of the c8s module. conformance-images.yml
# publishes it and prints the digest to pin in fixture.go.
# Bump: crane digest golang:1.27.3
FROM --platform=$BUILDPLATFORM golang:1.27.3@sha256:f24164268fc1e741bbdc0066dbadcf1c8426c5a8489f0729c02c3905a53032fd AS builder

WORKDIR /src
COPY go.mod go.sum ./
COPY test/tdxpod/fixtures/pod-connected/ ./test/tdxpod/fixtures/pod-connected/
RUN GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /pod-netcheck ./test/tdxpod/fixtures/pod-connected/netcheck

# Bump: crane digest gcr.io/distroless/static:nonroot
FROM gcr.io/distroless/static:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329
COPY --from=builder /pod-netcheck /usr/local/bin/pod-netcheck
ENTRYPOINT ["/usr/local/bin/pod-netcheck"]
