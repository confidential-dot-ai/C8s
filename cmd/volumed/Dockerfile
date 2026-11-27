# Bump: crane digest debian:bookworm-slim
FROM debian:bookworm-slim@sha256:e67eeead736ff7bbe258ef088bff683635c561b1fcfefad0806c1df4ab49ce0e

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
