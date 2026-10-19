# A conformance image: BASE with the reporter as its sleep, first on PATH.
# Its configuration, entrypoint and environment are BASE's.
ARG BASE
FROM ${BASE}
COPY --chmod=0755 sleep /usr/local/bin/sleep
