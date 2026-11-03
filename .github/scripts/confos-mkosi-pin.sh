#!/usr/bin/env bash
# Print the mkosi pin a confos commit's own base workflow uses.
#
#   confos-mkosi-pin.sh CONFOS_SHA
#
# Prints "MKOSI_SHA MKOSI_VERSION" from the single `systemd/mkosi@<sha> # v<n>`
# line in that commit's .github/workflows/base.yml. The manifest's mkosi pin is
# derived from this, never chosen: pin-watch writes it, and pin hygiene fails
# when the manifest no longer agrees with it. CONFOS_RAW_BASE overrides where
# the file is fetched from (tests point it at a file:// tree).

set -euo pipefail

die() {
  echo "confos-mkosi-pin: $*" >&2
  exit 1
}

[[ $# -eq 1 ]] || die "usage: confos-mkosi-pin.sh CONFOS_SHA"
confos=$1
[[ "$confos" =~ ^[0-9a-f]{40}$ ]] || die "confos ref must be a full lowercase 40-hex SHA"

base=${CONFOS_RAW_BASE:-https://raw.githubusercontent.com/confidential-dot-ai/confidential-os-builder}
base_yml=$(curl -fsSL --retry 3 "$base/$confos/.github/workflows/base.yml") ||
  die "could not fetch confos $confos base.yml"
mapfile -t lines < <(grep -oE 'systemd/mkosi@[0-9a-f]{40} # v[0-9.]+' <<<"$base_yml" || true)
((${#lines[@]} == 1)) ||
  die "expected exactly one mkosi pin in confos $confos base.yml; found ${#lines[@]}"
sha=$(grep -oE '[0-9a-f]{40}' <<<"${lines[0]}")
version=$(grep -oE 'v[0-9.]+$' <<<"${lines[0]}")
printf '%s %s\n' "$sha" "$version"
