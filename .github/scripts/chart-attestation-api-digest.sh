#!/usr/bin/env bash
# Read or write the chart's copy of the attestation-api digest.
#
#   chart-attestation-api-digest.sh get [COMPONENTS_YAML]
#   chart-attestation-api-digest.sh set sha256:HEX [COMPONENTS_YAML]
#
# .github/build-pins.json's attestation_api_digest is the pin; the chart's
# attestationApi pinnedDigest (what `c8s install` runs on the host) is a copy
# of it. pin-watch writes the copy with `set`, pin-hygiene compares `get` to
# the manifest, and a hand bump runs `set`. The file is rewritten in place
# with the one line changed, so its comments survive. Exactly one pinnedDigest
# line must exist; anything else is an error, not a guess.

set -euo pipefail

die() {
  echo "chart-attestation-api-digest: $*" >&2
  exit 1
}

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
default_values="$script_dir/../../charts/lib/files/components.yaml"
pattern='^[[:space:]]*pinnedDigest:[[:space:]]*sha256:[0-9a-f]{64}$'

current() {
  local values=$1 lines
  lines=$(grep -cE "$pattern" "$values" || true)
  [[ "$lines" == 1 ]] || die "expected exactly one pinnedDigest in $values, found $lines"
  grep -E "$pattern" "$values" | grep -oE 'sha256:[0-9a-f]{64}'
}

case "${1:-}" in
  get)
    [[ $# -le 2 ]] || die "usage: get [COMPONENTS_YAML]"
    current "${2:-$default_values}"
    ;;
  set)
    [[ $# -ge 2 && $# -le 3 ]] || die "usage: set sha256:HEX [COMPONENTS_YAML]"
    digest=$2 values=${3:-$default_values}
    [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || die "$digest is not an OCI digest (sha256:<64 lowercase hex>)"
    current "$values" >/dev/null
    sed -i -E "s|^([[:space:]]*pinnedDigest:[[:space:]]*)sha256:[0-9a-f]{64}$|\1${digest}|" "$values"
    [[ "$(current "$values")" == "$digest" ]] || die "pinnedDigest in $values was not rewritten to $digest"
    ;;
  *)
    die "usage: get [COMPONENTS_YAML] | set sha256:HEX [COMPONENTS_YAML]"
    ;;
esac
