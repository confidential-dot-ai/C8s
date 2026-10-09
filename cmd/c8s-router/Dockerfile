# Bump: crane digest nginxinc/nginx-unprivileged:1.30.5-alpine-slim
FROM nginxinc/nginx-unprivileged:1.30.5-alpine-slim@sha256:3af0c10d960cc2502427fe1219c52989d309e7d65596869c60a34fd2fa2406f0

COPY build/c8s /c8s

ENTRYPOINT ["/c8s", "router"]
