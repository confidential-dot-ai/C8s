#!/usr/bin/env bash
# The browser customer's check: c8s-verify-js, built at the pinned commit,
# attests the front door over attest-pq and sends one request through the
# over-encrypted tunnel to the gateway. Nothing skips; any failure fails.
#
# Usage: verify-js.sh <router-workload> <api-key-file> <allowlist-file>
#   allowlist-file holds the canonical bytes the caller already fetched; the
#   bytes this client fetches from /allowlist must equal them.
# Env: GUEST_IP, IMAGE_MANIFEST, CIE_DIR. Needs node >= 20, npm, cargo and
# wasm-pack (the verifier WASM is built from the pinned attestation-rs).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
. "$here/pins.env"
: "${GUEST_IP:?}" "${IMAGE_MANIFEST:?}" "${CIE_DIR:?}"
[ $# -eq 3 ] || { echo "usage: $0 <router-workload> <api-key-file> <allowlist-file>" >&2; exit 2; }

src=$CIE_DIR/verify-js-src
api_key_file=$(realpath "$2")
allowlist=$(realpath "$3")
if [ ! -e "$src/src/wasm/attestation_wasm_bg.wasm" ]; then
  rm -rf "$src"
  git init -q "$src"
  git -C "$src" fetch -q --depth 1 "https://github.com/$VERIFY_JS_REPO.git" "$VERIFY_JS_COMMIT"
  git -C "$src" checkout -q FETCH_HEAD
  git -C "$src" submodule update -q --init --depth 1 vendor/attestation-rs
  (cd "$src" && npm ci --no-audit --no-fund && npm run build:wasm)
fi

cd "$src"
VERIFY_JS_SRC=$src node --import tsx "$here/verify-js.mjs" \
  --url "https://$GUEST_IP" --server-name c8s.local --image-manifest "$IMAGE_MANIFEST" \
  --workload "$1" --api-key-file "$api_key_file" --allowlist "$allowlist"
