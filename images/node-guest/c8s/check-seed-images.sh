#!/usr/bin/env bash
set -euo pipefail

# The seed may grant authority only to images used by rendered workloads.
if ! jq -e --rawfile images "$2" '
    ($images | split("\n") | map(select(length > 0) | split("@") | last)) as $rendered |
    [.workloads[] | (.containers[]?, .initContainers[]?)] as $seed |
    ($seed | length > 0) and all($seed[];
        .digest as $digest | $rendered | index($digest) != null)
' "$1" >/dev/null; then
    echo "c8s sync: FATAL seed image/digest is absent from rendered workloads" >&2
    exit 1
fi
