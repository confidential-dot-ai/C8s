#!/usr/bin/env bash
# Lint and render the C8s Helm chart for .github/workflows/chart.yml. Runs two
# checks in sequence (they always ran together, unconditionally):
#   1. helm lint
#   2. helm template                       (renders cleanly)
#
# The image tags/digests below are CI placeholders: helm must resolve every
# `required`/digest reference for lint+template to pass, but nothing is deployed,
# so opaque dummy values are fine. They're defined once here instead of being
# repeated across three near-identical workflow steps.
#
# Inputs (env):
#   CHART_DIR   chart directory to lint/template.

set -euo pipefail

: "${CHART_DIR:?CHART_DIR must be set}"

# Shared --set flags for every check below. The digests are well-formed but
# arbitrary sha256 placeholders (lint/template only need them to parse).
common_set=(
  --set image.tag=ci
  --set attestationApi.image.tag=ci
  --set cds.image.tag=ci
  --set armtlsMesh.image.tag=ci
  --set nriImagePolicy.image.tag=ci
  --set nriImagePolicy.image.digest=sha256:aaaa000000000000000000000000000000000000000000000000000000000000
  --set cds.image.digest=sha256:0000000000000000000000000000000000000000000000000000000000000001
  # router has no default upstream; a c8s-<id> headless-Service address (what
  # `c8s install --upstream` derives, recognized as mesh-wrapped) is the
  # representative configuration.
  --set-string router.upstream.address=c8s-infer.c8s-system.svc.cluster.local:8000
  # The default policy mode is fail-closed, which requires every digest-pinned
  # C8s component to be covered in the allowlist floor or the plugin would deny
  # it on its own node. deriveComponents auto-covers the C8s images from their
  # digests (what `c8s install --resolve-digests` turns on) — the representative
  # way to render a valid fail-closed config without hand-listing CI placeholders.
  --set nriImagePolicy.bootstrapAllowlist.deriveComponents=true
  # The chart refuses to render a release that pins no CDS guest identity.
  --set-string cds.measurements[0]=000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001
)

echo "::group::helm lint"
helm lint "$CHART_DIR" "${common_set[@]}"
echo "::endgroup::"

# --kube-version: the chart's kubeVersion floor (1.30) is above helm 3.14's
# default simulated capability (1.29), so template needs it pinned explicitly.
echo "::group::helm template"
helm template c8s "$CHART_DIR" \
  --kube-version v1.30.0 \
  --namespace c8s-system \
  "${common_set[@]}" \
  > /dev/null
echo "::endgroup::"
