#!/usr/bin/env bash
# shellcheck disable=SC2034 # Source selection outputs are consumed by callers.

select_image_source() {
    local ref=$1 local_images_dir=$2 registry=$3 image layout
    IMAGE_SOURCE_REF=$ref
    IMAGE_MANIFEST_ARGS=()
    IMAGE_COPY_ARGS=()
    if [[ -n "$local_images_dir" && "$ref" == "$registry/"* ]]; then
        image=${ref#"$registry/"}
        layout=${image%%@*}
        layout=${layout%%:*}
        layout="$local_images_dir/$layout"
        [[ -f "$layout/oci-layout" && -f "$layout/index.json" ]] || {
            echo "image-source: local OCI layout missing for '$ref': $layout" >&2
            return 1
        }
        IMAGE_SOURCE_REF="$local_images_dir/$image"
        IMAGE_MANIFEST_ARGS=(--oci-layout)
        IMAGE_COPY_ARGS=(--from-oci-layout)
    fi
}
