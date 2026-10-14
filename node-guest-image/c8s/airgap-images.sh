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

# Media types whose blobs name further blobs; configs and layers are leaves.
manifest_media='(manifest|index)[^/]*\+json$'

# Succeed only when layout $1 tags image $2 as "measured" exactly as a fresh
# `oras cp` does and holds exactly the blobs that image references, each at its
# descriptor's size and sha256. The archive below packs the whole blobs tree,
# so a reused cache must match what a fresh copy would produce. Only the
# top-level descriptor is unpinned; every other one is inside a verified blob.
cached_layout_complete() {
    local layout=$1 digest=$2 descriptor blob size media path children root=1
    local -a queue
    local -A seen=()
    [[ -f "$layout/index.json" ]] || return 1
    descriptor=$(jq -ce --arg digest "$digest" \
        '[.manifests[] | select(.digest == $digest and .annotations == {"org.opencontainers.image.ref.name": "measured"} and keys == ["annotations", "digest", "mediaType", "size"])] | if length == 1 then .[0] else error("not tagged") end' \
        "$layout/index.json" 2>/dev/null) || return 1
    queue=("$descriptor")
    while (( ${#queue[@]} )); do
        descriptor=${queue[0]}
        queue=("${queue[@]:1}")
        IFS=$'\t' read -r blob size media < <(jq -r '[.digest, .size, .mediaType // ""] | @tsv' <<<"$descriptor")
        [[ "$blob" =~ ^sha256:[a-f0-9]{64}$ && -n "$media" ]] || return 1
        [[ -z "${seen[$blob]:-}" ]] || continue
        seen[$blob]=1
        path="$layout/blobs/sha256/${blob#sha256:}"
        [[ -f "$path" && ! -L "$path" && "$(stat -c %s "$path")" == "$size" ]] || return 1
        [[ "$(sha256sum "$path" | cut -d' ' -f1)" == "${blob#sha256:}" ]] || return 1
        if (( root )); then
            # The pinned digest must name an index or manifest that declares
            # the same media type, or its children would go unchecked.
            [[ "$media" =~ $manifest_media ]] || return 1
            jq -e --arg media "$media" '.mediaType == $media' "$path" >/dev/null 2>&1 || return 1
            root=0
        fi
        # oras copies subjects too, so they belong to a complete layout.
        if [[ "$media" =~ $manifest_media ]]; then
            children=$(jq -c '(.subject // empty), (.config // empty), (.manifests // [])[], (.layers // [])[], (.blobs // [])[]' "$path") || return 1
            [[ -z "$children" ]] || mapfile -t -O "${#queue[@]}" queue <<<"$children"
        fi
    done
    # tar archives directories too: allow only blobs/sha256 and its blobs.
    [[ "$(find "$layout/blobs" -mindepth 1 | wc -l)" == $(( ${#seen[@]} + 1 )) ]]
}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
count=0
declare -A kept=()
while IFS= read -r ref || [[ -n "$ref" ]]; do
    [[ "$ref" =~ ^[^[:space:]@]+@sha256:[a-f0-9]{64}$ ]] || {
        echo "airgap-images: expected a digest-pinned image, got '$ref'" >&2
        exit 1
    }
    digest=${ref##*@}
    layout="$cache_dir/oci-${digest#sha256:}"
    kept[$layout]=1
    # Copy the complete index, including every referenced manifest. Selecting
    # a platform here would replace the original index with a child digest.
    select_image_source "$ref" "$local_images_dir" "$c8s_registry"
    # The digest pins the content, so a verified cached copy needs no network.
    # Anything short of that is discarded rather than topped up.
    if cached_layout_complete "$layout" "$digest"; then
        echo "airgap-images: reusing verified cache for $ref"
    else
        rm -rf "$layout"
        oras cp "${IMAGE_COPY_ARGS[@]}" --to-oci-layout "$IMAGE_SOURCE_REF" "$layout:measured"
    fi
    jq -e --arg digest "$digest" \
        '[.manifests[] | select(.digest == $digest and .annotations["org.opencontainers.image.ref.name"] == "measured")] | length == 1' \
        "$layout/index.json" >/dev/null
    # containerd uses this annotation as the exact imported image name.
    # Only the outer layout index changes; all referenced blobs stay intact.
    jq -S --arg ref "$ref" --arg digest "$digest" \
        '.manifests = [.manifests[] | select(.digest == $digest and .annotations["org.opencontainers.image.ref.name"] == "measured") | .annotations = {"io.containerd.image.name": $ref, "org.opencontainers.image.ref.name": $ref}]' \
        "$layout/index.json" > "$work/index.json"
    # The bytes oras writes; a cached layout's copy is never archived.
    printf '%s' '{"imageLayoutVersion":"1.0.0"}' > "$work/oci-layout"
    # Fixed metadata and ordering make repeated builds byte-identical.
    tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner \
        --format=gnu --mode='u+rwX,go+rX,go-w' -cf "$work/image.tar" \
        -C "$work" index.json oci-layout -C "$layout" blobs
    install -m 0644 "$work/image.tar" "$output_dir/c8s-${count}.tar"
    count=$((count + 1))
done < "$images_file"
(( count > 0 )) || { echo "airgap-images: no core images were rendered" >&2; exit 1; }
# The cache is persisted across CI runs; keep only the layouts this list pins.
for layout in "$cache_dir"/oci-*; do
    [[ ! -e "$layout" || -n "${kept[$layout]:-}" ]] || rm -rf "$layout"
done
