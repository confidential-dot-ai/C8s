#!/usr/bin/env bash
# Capture fixture pins only after verified disk comparison and both pushes.
set -euo pipefail
work=$1 variant=$2 run=$3 overlay=$4
[[ "$overlay" =~ ^[0-9a-f]{40}$ && "$variant" == "rke2-tdx-recovery-${overlay:0:12}" && "$run" =~ ^[1-9][0-9]*$ ]] || {
    echo 'invalid isolated fixture publication identity' >&2; exit 1; }
repository=ghcr.io/confidential-dot-ai/node-guest-base
digest() { sha256sum "$1" | cut -d' ' -f1; }
declare -A refs
for field in image artifact; do
    suffix=-05211a8
    [[ "$field" != image ]] || suffix=-cdi-05211a8
    descriptor=$(timeout 120 oras manifest fetch --descriptor "$repository:$variant$suffix" | jq -er '.digest')
    [[ "$descriptor" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo 'invalid immutable descriptor' >&2; exit 1; }
    refs[$field]="$repository@$descriptor"
done
timeout 120 oras manifest fetch "${refs[artifact]}" > "$work/artifact-manifest.json"
layer() {
    # The digest of the single published layer titled $1.
    jq -er --arg name "$1" '[.layers[] | select(.annotations["org.opencontainers.image.title"] == $name)] |
        if length == 1 then .[0].digest else error("ambiguous published layer: " + $name) end' "$work/artifact-manifest.json"
}
manifest_hash=$(digest "$work/manifest.json")
disk=$(jq -er '.outputs.disk_image.sha256' "$work/manifest.json")
[[ "$(layer manifest.json)" == "sha256:$manifest_hash" && "$(layer disk.raw)" == "sha256:$disk" ]] || {
    echo 'published fixture differs from the verified build' >&2; exit 1; }
jq -S --arg run "$run" --arg image "${refs[image]}" --arg artifact "${refs[artifact]}" \
    --arg manifest "$manifest_hash" --arg disk "$disk" --arg overlay "$overlay" \
    --arg components "$(digest "$work/runtime-components.json")" '{
    schema: 1, source: .baseline, profileSource: .baseline, buildRun: $run,
    image: $image, artifact: $artifact, manifestSHA256: $manifest, diskSHA256: $disk,
    meshImage: "ghcr.io/confidential-dot-ai/armtls-mesh@sha256:e05ccc28f168972c86ccc1bdb899a371264a38a0ef69a2f0eece6d9813baee27",
    recoveryFixture: true, overlaySource: $overlay, controllerSHA256: .controllerSHA256,
    baselineDiskSHA256: "eb2dffb9712048ad23a2a62c04441c85f708cad60a846ce8cf4c5d7f4b610bb6",
    runtimeComponentsSHA256: $components}' "$work/runtime-components.json" > "$work/image.json"
echo "Fixture receipt SHA256: $(digest "$work/image.json")"
