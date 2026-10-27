# Bump: crane digest gcr.io/distroless/static:nonroot
FROM gcr.io/distroless/static:nonroot@sha256:d62067879de890a1def9da0e7766b7d20810a5e5555cef8506b752437d7a3e88

# The `/c8s` binary path is hardcoded in the c8s-cert-wait gate command
# (internal/helmchart/c8s/templates/_helpers.tpl "c8s.getCertContainers" and
# internal/webhook/pod_mutator.go "certWaitContainer") because command bypasses
# the ENTRYPOINT. If you move the COPY target or change the ENTRYPOINT, update
# that command too.
COPY build/c8s /c8s

ENTRYPOINT ["/c8s"]
