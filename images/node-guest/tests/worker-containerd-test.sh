#!/usr/bin/env bash
# Check the worker image's effective containerd configuration: every
# ordinary-pod handler must run the measured runtime wrapper. The image bakes
# the main config, so containerdcheck reads it in place of RKE2's rendering
# and merges the drop-ins containerd imports.
set -euo pipefail

TESTS_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(cd "$TESTS_DIR/../../.." && pwd)

EXTRA=$(mktemp -d)
trap 'rm -rf -- "$EXTRA"' EXIT
bash "$TESTS_DIR/stage-worker-extra.sh" "$EXTRA"

CONFIG_DIR=$EXTRA/var/lib/rancher/rke2/agent/etc/containerd
CONFIG=$CONFIG_DIR/config.toml
[ -f "$CONFIG" ] \
    || { echo "the worker image bakes no containerd main config at ${CONFIG#"$EXTRA"}" >&2; exit 1; }
[ -d "$CONFIG_DIR/config-v3.toml.d" ] \
    || { echo "the worker image bakes no containerd drop-in directory" >&2; exit 1; }
cd "$REPO_DIR"
go run ./images/node-guest/tools/containerdcheck -config-dir "$CONFIG_DIR" -config "$CONFIG"
