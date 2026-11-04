# Bump: crane digest debian:bookworm-slim
FROM debian:bookworm-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3

# cryptsetup-bin provides cryptsetup AND veritysetup, the two tools the daemon
# shells out to (internal/cmds/volumed/systemops.go). The mount itself is a
# syscall, so no mount(8) is needed. Distroless cannot carry these, which is
# why volumed has its own image rather than reusing the operator image.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        cryptsetup-bin \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /app

COPY build/c8s /app/c8s
RUN chmod +x /app/c8s

ENTRYPOINT ["/app/c8s", "volumed"]
