# The conformance images: each base of test/conformance/backends/common.sh's
# image_ref with the reporter as its sleep, first on PATH, one stage per
# logical name. Configuration, entrypoint and environment are the base's.

FROM docker.io/library/debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587 AS model-server
COPY --chmod=0755 sleep /usr/local/bin/sleep

FROM docker.io/library/python:3.12-alpine@sha256:1b668429b3511ab407d8e00648891631b0b1a4d7e15e3ca70f38ab5b91ad4ab4 AS tenant-app
COPY --chmod=0755 sleep /usr/local/bin/sleep

FROM docker.io/library/alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc AS job-runner
COPY --chmod=0755 sleep /usr/local/bin/sleep
