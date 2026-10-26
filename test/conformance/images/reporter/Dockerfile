# The conformance image model-server (test/conformance/backends/common.sh's
# image_ref) with the reporter as its sleep, first on PATH, and curl, which
# the steps run in the pod to reach the node's sockets; configuration,
# entrypoint and environment are the base's. Only model-server runs a pinned
# sleep whose files the steps read.
FROM docker.io/library/debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
COPY --chmod=0755 sleep /usr/local/bin/sleep
