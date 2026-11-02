# Bump: crane digest debian:bookworm-slim
FROM debian:bookworm-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        util-linux \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /etc/nri/conf.d /var/log/nri-image-policy /var/run/nri

COPY build/c8s /usr/local/bin/c8s
COPY cmd/nri-image-policy/enable-nri.sh /usr/local/bin/enable-nri.sh
RUN chmod +x /usr/local/bin/c8s /usr/local/bin/enable-nri.sh \
    && ln -s /usr/local/bin/c8s /usr/local/bin/nri-image-policy

ENTRYPOINT ["/usr/local/bin/c8s", "nri-image-policy"]
CMD ["--config", "/etc/nri/conf.d/image-policy.yaml"]
