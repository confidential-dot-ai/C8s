# The conformance image tenant-app (test/conformance/backends/common.sh's
# image_ref): Alpine's python with the programs the steps run in it, on PATH,
# so that no step passes a program as a string, and curl, which the steps run
# in the pod to reach the node's sockets.
FROM docker.io/library/python:3.12-alpine@sha256:1b668429b3511ab407d8e00648891631b0b1a4d7e15e3ca70f38ab5b91ad4ab4
RUN apk add --no-cache curl
COPY --chmod=0755 c8s-echo-api c8s-hello-api c8s-udp-listen c8s-udp-send /usr/local/bin/
