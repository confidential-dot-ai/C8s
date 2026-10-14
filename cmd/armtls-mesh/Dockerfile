# Bump: crane digest debian:bookworm-slim
FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        ipset \
        iptables \
        libssl3 \
        libtss2-esys-3.0.2-0 \
        libtss2-tctildr0 \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /app

COPY build/c8s /app/c8s
RUN chmod +x /app/c8s

ENTRYPOINT ["/app/c8s", "armtls-mesh"]
