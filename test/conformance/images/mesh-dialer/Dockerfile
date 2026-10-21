# The conformance image mesh-dialer: the mesh peer (tools/armtls-dial) on
# PATH, so the steps run it in a pod that takes no file from the harness.
# Repo-root build context; the tool needs only pkg/ of the c8s module.
# Bump: crane digest golang:1.27.3
FROM golang:1.27.3@sha256:f24164268fc1e741bbdc0066dbadcf1c8426c5a8489f0729c02c3905a53032fd AS builder

WORKDIR /src
COPY go.mod go.sum ./
COPY test/conformance/tools/armtls-dial/go.mod test/conformance/tools/armtls-dial/go.sum ./test/conformance/tools/armtls-dial/
RUN GOWORK=off go -C test/conformance/tools/armtls-dial mod download
COPY pkg/ ./pkg/
COPY test/conformance/tools/armtls-dial/ ./test/conformance/tools/armtls-dial/
RUN GOWORK=off CGO_ENABLED=0 go build -C test/conformance/tools/armtls-dial -ldflags="-s -w" -o /armtls-dial .

# busybox, for the sh the metal backend's agent runs in.
# Bump: crane digest busybox:1.36.1
FROM busybox:1.36.1@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662
COPY --from=builder /armtls-dial /usr/local/bin/armtls-dial
