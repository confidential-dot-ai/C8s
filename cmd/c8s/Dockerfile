# Bump: crane digest gcr.io/distroless/static:nonroot
FROM gcr.io/distroless/static:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329

# The `/c8s` binary path is hardcoded in the c8s-cert-wait gate command
# (internal/helmchart/c8s/templates/_helpers.tpl "c8s.getCertContainers" and
# internal/webhook/pod_mutator.go "certWaitContainer") because command bypasses
# the ENTRYPOINT. If you move the COPY target or change the ENTRYPOINT, update
# that command too.
COPY build/c8s /c8s

ENTRYPOINT ["/c8s"]
