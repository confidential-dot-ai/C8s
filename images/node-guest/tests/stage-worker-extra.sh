#!/usr/bin/env bash
# Stage the worker image's baked tree into DEST, the way
# images/node-guest/build stages it for a worker build: this profile's
# mkosi.extra, and the c8s profile's files worker/shared names, with their
# modes. A path baked by both profiles has no defined precedence, so it is
# refused here.
set -euo pipefail

DEST=${1:?usage: stage-worker-extra.sh DEST}
IMAGE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

mkdir -p "$DEST"
cp -a "$IMAGE_DIR/worker/mkosi.extra/." "$DEST/"
while read -r shared; do
    source=$IMAGE_DIR/c8s/mkosi.extra/$shared
    [ -f "$source" ] || { echo "worker/shared names $shared, which the c8s profile does not bake" >&2; exit 1; }
    [ ! -e "$DEST/$shared" ] || { echo "both profiles bake $shared" >&2; exit 1; }
    install -D -m "$(stat -c %a "$source")" "$source" "$DEST/$shared"
done < <(grep -Ev '^[[:space:]]*(#|$)' "$IMAGE_DIR/worker/shared")
