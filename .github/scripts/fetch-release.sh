#!/usr/bin/env bash
# fetch-release.sh <owner>/<repo> <tag> <asset> <out>: download a GitHub
# release asset from the c8s mirror (https://confosaptmirrorae526a.blob.core.windows.net/gh-releases/<owner>/<repo>/<tag>/<asset>),
# falling back to GitHub, whose release downloads return 504 under burst load.
# Callers verify the asset's pinned sha256; that check is what makes the
# mirror safe to use.
set -euo pipefail
[ $# -eq 4 ] || { echo "usage: $0 <owner>/<repo> <tag> <asset> <out>" >&2; exit 2; }
mirror=https://confosaptmirrorae526a.blob.core.windows.net/gh-releases
curl -fsSL --retry 3 --connect-timeout 20 -o "$4" "$mirror/$1/$2/$3" ||
  curl -fsSL --retry 8 --retry-max-time 300 --retry-all-errors --connect-timeout 20 -o "$4" "https://github.com/$1/releases/download/$2/$3"
