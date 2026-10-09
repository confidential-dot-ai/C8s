#!/usr/bin/env bash
# Build the canonical per-image Docker matrix consumed by docker.yml and the
# all-components release rebuild in semver-tag.yml.
#
# A component image is included when ANY of:
#   - this is a manual workflow_dispatch -> rebuild every image (no diff base)
#   - shared code changed (SHARED=true)  -> pkg/**, root internal/**, go.mod, …
#   - the component's own paths changed   (its <X>=true flag)
#
# The workflow_dispatch fan-out is what makes the manual rebuild work: a
# dispatch has no before/after diff, so docker.yml skips paths-filter and every
# per-component flag arrives empty here. Build all of them.
#
# Components NOT included are emitted as a parallel `retag_matrix` so the
# `retag-unchanged` job in docker.yml can copy each one's current `:main`
# manifest under `:<short-sha>` — even when this run's filter rebuilt only a subset.
#
# Inputs (env), each "true"/"false" from the dorny/paths-filter step:
#   SHARED             shared-core || shared-cmdsutil || shared-root
#   C8S, CDS, GET_CERT, ARMTLS_MESH, NRI_IMAGE_POLICY, VOLUMED, ROUTER
#   GITHUB_EVENT_NAME  the triggering event; "workflow_dispatch" fans out to all
#                      (paths-filter is skipped on dispatch, so the flags above
#                      are empty and this is the only signal to build them)
#   GITHUB_OUTPUT      step output file; we append `matrix`, `has_images`,
#                      `retag_matrix`, and `has_retag`.
#
# Output (GITHUB_OUTPUT):
#   has_images=true|false
#   matrix={"include":[{binary,image,dockerfile}, …]}
#   has_retag=true|false
#   retag_matrix={"include":[{binary,image}, …]}

set -euo pipefail

include=()
exclude=()
maybe_add() {
  local changed="$1" binary="$2" image="$3" dockerfile="$4"
  if [[ "${GITHUB_EVENT_NAME:-}" == "workflow_dispatch" || "$SHARED" == "true" || "$changed" == "true" ]]; then
    include+=("{\"binary\":\"$binary\",\"image\":\"$image\",\"dockerfile\":\"$dockerfile\"}")
  else
    exclude+=("{\"binary\":\"$binary\",\"image\":\"$image\"}")
  fi
}

maybe_add "$C8S" c8s ghcr.io/confidential-dot-ai/c8s-operator cmd/c8s/Dockerfile
maybe_add "$CDS" cds ghcr.io/confidential-dot-ai/cds cmd/cds/Dockerfile
maybe_add "$GET_CERT" get-cert ghcr.io/confidential-dot-ai/get-cert cmd/get-cert/Dockerfile
maybe_add "$ARMTLS_MESH" armtls-mesh ghcr.io/confidential-dot-ai/armtls-mesh cmd/armtls-mesh/Dockerfile
maybe_add "$NRI_IMAGE_POLICY" nri-image-policy ghcr.io/confidential-dot-ai/nri-image-policy cmd/nri-image-policy/Dockerfile
maybe_add "$VOLUMED" volumed ghcr.io/confidential-dot-ai/volumed cmd/volumed/Dockerfile
maybe_add "${ROUTER:-false}" c8s-router ghcr.io/confidential-dot-ai/c8s-router cmd/c8s-router/Dockerfile

if [[ ${#include[@]} -eq 0 ]]; then
  echo 'has_images=false' >> "$GITHUB_OUTPUT"
  echo 'matrix={"include":[]}' >> "$GITHUB_OUTPUT"
else
  matrix=$(IFS=,; printf '{"include":[%s]}' "${include[*]}")
  echo 'has_images=true' >> "$GITHUB_OUTPUT"
  echo "matrix=$matrix" >> "$GITHUB_OUTPUT"
fi

if [[ ${#exclude[@]} -eq 0 ]]; then
  echo 'has_retag=false' >> "$GITHUB_OUTPUT"
  echo 'retag_matrix={"include":[]}' >> "$GITHUB_OUTPUT"
else
  retag_matrix=$(IFS=,; printf '{"include":[%s]}' "${exclude[*]}")
  echo 'has_retag=true' >> "$GITHUB_OUTPUT"
  echo "retag_matrix=$retag_matrix" >> "$GITHUB_OUTPUT"
fi
