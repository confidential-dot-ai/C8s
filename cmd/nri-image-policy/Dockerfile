# Bump: crane digest debian:bookworm-slim
FROM debian:bookworm-slim@sha256:e67eeead736ff7bbe258ef088bff683635c561b1fcfefad0806c1df4ab49ce0e

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
