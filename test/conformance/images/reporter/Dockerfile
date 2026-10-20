# The conformance image model-server (test/conformance/backends/common.sh's
# image_ref) with the reporter as its sleep, first on PATH; configuration,
# entrypoint and environment are the base's. Only model-server runs a pinned
# sleep whose files the steps read.
FROM docker.io/library/debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
COPY --chmod=0755 sleep /usr/local/bin/sleep
