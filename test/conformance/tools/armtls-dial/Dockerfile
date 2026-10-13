# Bump: crane digest golang:1.27
FROM golang:1.27@sha256:007a316059246276cb214df93950be77837545dc78007a73e0291a4963d5d3bf AS builder

WORKDIR /src
# Repo-root build context (the module replaces c8s => ../../../..); .dockerignore must keep these paths.
COPY go.mod go.sum ./
COPY pkg/ ./pkg/
COPY test/conformance/tools/armtls-dial/ ./test/conformance/tools/armtls-dial/
RUN CGO_ENABLED=0 go build -C test/conformance/tools/armtls-dial -ldflags="-s -w" -o /armtls-dial .

# busybox, not distroless: the pod idles on `sleep 3600` and the steps exec the binary.
# Bump: crane digest docker.io/library/busybox:1.36.1
FROM docker.io/library/busybox:1.36.1@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662
COPY --from=builder /armtls-dial /armtls-dial
CMD ["sleep", "3600"]
