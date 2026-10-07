#!/usr/bin/env bash
# Preserve complete pinned OCI images for RKE2's offline importer. Keeping the
# original manifest/index bytes makes the pod image pin and NRI digest agree.
set -euo pipefail

[[ $# -ge 3 && $# -le 5 ]] || { echo "usage: airgap-images.sh IMAGES_FILE CACHE_DIR OUTPUT_DIR [LOCAL_IMAGES_DIR [C8S_REGISTRY]]" >&2; exit 2; }
images_file=$1
cache_dir=$2
output_dir=$3
local_images_dir=${4:-}
c8s_registry=${5:-ghcr.io/confidential-dot-ai}
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=node-guest-image/c8s/image-source.sh
source "$SCRIPT_DIR/image-source.sh"
mkdir -p "$cache_dir" "$output_dir"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
count=0
while IFS= read -r ref || [[ -n "$ref" ]]; do
    [[ "$ref" =~ ^[^[:space:]@]+@sha256:[a-f0-9]{64}$ ]] || {
        echo "airgap-images: expected a digest-pinned image, got '$ref'" >&2
        exit 1
    }
    digest=${ref##*@}
    layout="$cache_dir/oci-${digest#sha256:}"
    # Copy the complete index, including every referenced manifest. Selecting
    # a platform here would replace the original index with a child digest.
    select_image_source "$ref" "$local_images_dir" "$c8s_registry"
    oras cp "${IMAGE_COPY_ARGS[@]}" --to-oci-layout "$IMAGE_SOURCE_REF" "$layout:measured"
    jq -e --arg digest "$digest" \
        '[.manifests[] | select(.digest == $digest and .annotations["org.opencontainers.image.ref.name"] == "measured")] | length == 1' \
        "$layout/index.json" >/dev/null
    # containerd uses this annotation as the exact imported image name.
    # Only the outer layout index changes; all referenced blobs stay intact.
    jq -S --arg ref "$ref" --arg digest "$digest" \
        '.manifests = [.manifests[] | select(.digest == $digest and .annotations["org.opencontainers.image.ref.name"] == "measured") | .annotations = {"io.containerd.image.name": $ref, "org.opencontainers.image.ref.name": $ref}]' \
        "$layout/index.json" > "$work/index.json"
    cp "$layout/oci-layout" "$work/oci-layout"
    # Fixed metadata and ordering make repeated builds byte-identical.
    tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner \
        --format=gnu --mode='u+rwX,go+rX,go-w' -cf "$work/image.tar" \
        -C "$work" index.json oci-layout -C "$layout" blobs
    install -m 0644 "$work/image.tar" "$output_dir/c8s-${count}.tar"
    count=$((count + 1))
done < "$images_file"
(( count > 0 )) || { echo "airgap-images: no core images were rendered" >&2; exit 1; }
