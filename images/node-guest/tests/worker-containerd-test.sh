#!/usr/bin/env bash
# Check the worker image's effective containerd configuration: every
# ordinary-pod handler must run the measured runtime wrapper. containerdcheck
# reads the main config the image bakes and merges the drop-ins containerd
# imports.
set -euo pipefail

TESTS_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(cd "$TESTS_DIR/../../.." && pwd)

CONFIG_DIR=$TESTS_DIR/../worker/mkosi.extra/etc/containerd
CONFIG=$CONFIG_DIR/config.toml
[ -f "$CONFIG" ] \
    || { echo "the worker image bakes no containerd main config" >&2; exit 1; }
[ -d "$CONFIG_DIR/conf.d" ] \
    || { echo "the worker image bakes no containerd drop-in directory" >&2; exit 1; }
cd "$REPO_DIR"
go run ./images/node-guest/tools/containerdcheck -config-dir "$CONFIG_DIR" -config "$CONFIG"
