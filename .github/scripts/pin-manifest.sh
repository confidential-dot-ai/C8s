#!/usr/bin/env bash
# Validate, export, and atomically update C8s's measured-build pin manifest.
# Each source pin is the commit SHA the builds check out beside the release
# tag that names it; see images/node-guest/README.md, "Component pins".

set -euo pipefail

tmp_path=
cleanup() {
  if [[ -n "$tmp_path" ]]; then
    rm -f -- "$tmp_path"
  fi
}
trap cleanup EXIT

die() {
  echo "error: $*" >&2
  exit 1
}

usage() {
  cat >&2 <<'EOF'
usage:
  pin-manifest.sh validate --manifest PATH
  pin-manifest.sh export --manifest PATH --domain DOMAIN
      --format github-env|github-output [--confos-override REF]
  pin-manifest.sh update --manifest PATH --domain node-image
      --confos SHA --confos-tag TAG --attest SHA --attest-tag TAG
      --attest-digest sha256:HEX --mkosi-sha SHA --mkosi-ver VERSION
EOF
  exit 2
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is required"
}

is_sha() {
  [[ "$1" =~ ^[0-9a-f]{40}$ ]]
}

is_version() {
  [[ "$1" =~ ^v(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*))*$ ]]
}

is_release_tag() {
  [[ "$1" =~ ^v(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)$ ]]
}

is_digest() {
  [[ "$1" =~ ^sha256:[0-9a-f]{64}$ ]]
}

require_sha() {
  is_sha "$1" || die "$2 must be a full lowercase 40-hex SHA"
}

require_digest() {
  is_digest "$1" || die "$2 must be an OCI digest, sha256:<64 lowercase hex>"
}

require_version() {
  is_version "$1" || die "$2 must look like v27 or v27.1"
}

require_release_tag() {
  is_release_tag "$1" || die "$2 must be a release tag like v0.6.0"
}

validate_override() {
  local ref=$1
  [[ -z "$ref" ]] && return
  if [[ ! "$ref" =~ ^[0-9A-Za-z][0-9A-Za-z._/-]{0,254}$ ]] ||
    [[ "$ref" == /* || "$ref" == */ || "$ref" == *. ||
      "$ref" == *..* || "$ref" == *//* || "$ref" == *"@{"* ]]; then
    die "confos override is not a safe Git ref"
  fi
}

validate_manifest() {
  local manifest=$1
  [[ -f "$manifest" ]] || die "manifest not found: $manifest"

  if ! jq empty "$manifest" >/dev/null; then
    die "manifest is not valid JSON: $manifest"
  fi

  if ! jq -e '
    def exact_keys($wanted):
      type == "object" and ((keys | sort) == ($wanted | sort));
    def sha:
      type == "string" and test("^[0-9a-f]{40}$");
    def version:
      type == "string"
      and test("^v(0|[1-9][0-9]*)(\\.(0|[1-9][0-9]*))*$");
    def release_tag:
      type == "string"
      and test("^v(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)$");
    def digest:
      type == "string" and test("^sha256:[0-9a-f]{64}$");

    (. | exact_keys(["schema_version", "builds"]))
    and (.schema_version == 3)
    and (.builds |
      exact_keys(["node-image"]))
    and (.builds["node-image"] |
      exact_keys([
        "confos_ref", "confos_tag", "attestation_rs_ref", "attestation_rs_tag",
        "attestation_api_digest", "mkosi_ref", "mkosi_version"
      ])
      and (.confos_ref | sha)
      and (.confos_tag | release_tag)
      and (.attestation_rs_ref | sha)
      and (.attestation_rs_tag | release_tag)
      and (.attestation_api_digest | digest)
      and (.mkosi_ref | sha)
      and (.mkosi_version | version))
  ' "$manifest" >/dev/null; then
    die "manifest schema or pin invariant is invalid: $manifest"
  fi

  # jq's normal object parser keeps the last duplicate key. Its streaming
  # parser retains each leaf occurrence, so enforce both the allowed raw paths
  # and path uniqueness before accepting the document.
  if ! jq --stream -s -e '
    [
      ["schema_version"],
      ["builds", "node-image", "confos_ref"],
      ["builds", "node-image", "confos_tag"],
      ["builds", "node-image", "attestation_rs_ref"],
      ["builds", "node-image", "attestation_rs_tag"],
      ["builds", "node-image", "attestation_api_digest"],
      ["builds", "node-image", "mkosi_ref"],
      ["builds", "node-image", "mkosi_version"]
    ] as $allowed
    | [.[] | select(length == 2) | .[0]] as $paths
    | (($paths | length) == ($paths | unique | length))
      and all(
        $paths[];
        . as $path | any($allowed[]; . == $path)
      )
  ' "$manifest" >/dev/null; then
    die "manifest contains a duplicate or unexpected JSON key: $manifest"
  fi
}

# The builds consume the *_REF SHAs and the attestation-api digest; the tags
# ride along for pin hygiene and pin-watch, which read the manifest through
# here and nowhere else.
export_pins() {
  local manifest=$1 domain=$2 format=$3 override=$4
  local confos confos_tag attest attest_tag attest_digest mkosi mkosi_version

  case "$domain" in
    node-image) ;;
    *) die "unknown export domain: $domain" ;;
  esac
  case "$format" in
    github-env | github-output) ;;
    *) die "unknown export format: $format" ;;
  esac

  validate_override "$override"
  validate_manifest "$manifest"
  confos=$(jq -er --arg domain "$domain" \
    '.builds[$domain].confos_ref' "$manifest")
  confos_tag=$(jq -er --arg domain "$domain" \
    '.builds[$domain].confos_tag' "$manifest")
  attest=$(jq -r --arg domain "$domain" \
    '.builds[$domain].attestation_rs_ref // ""' "$manifest")
  attest_tag=$(jq -r --arg domain "$domain" \
    '.builds[$domain].attestation_rs_tag // ""' "$manifest")
  attest_digest=$(jq -r --arg domain "$domain" \
    '.builds[$domain].attestation_api_digest // ""' "$manifest")
  mkosi=$(jq -er --arg domain "$domain" \
    '.builds[$domain].mkosi_ref' "$manifest")
  mkosi_version=$(jq -er --arg domain "$domain" \
    '.builds[$domain].mkosi_version' "$manifest")
  [[ -z "$override" ]] || confos=$override

  if [[ "$format" == github-env ]]; then
    printf 'CONFOS_REF=%s\nCONFOS_TAG=%s\n' "$confos" "$confos_tag"
    [[ -z "$attest" ]] || printf 'ATTESTATION_RS_REF=%s\nATTESTATION_RS_TAG=%s\nATTESTATION_API_DIGEST=%s\n' "$attest" "$attest_tag" "$attest_digest"
    printf 'MKOSI_REF=%s\nMKOSI_VERSION=%s\n' "$mkosi" "$mkosi_version"
  else
    printf 'confos=%s\nconfos_tag=%s\n' "$confos" "$confos_tag"
    [[ -z "$attest" ]] || printf 'attest=%s\nattest_tag=%s\nattest_digest=%s\n' "$attest" "$attest_tag" "$attest_digest"
    printf 'mkosi=%s\nmkosi_version=%s\n' "$mkosi" "$mkosi_version"
  fi
}

update_manifest() {
  local manifest=$1 domain=$2 confos=$3 confos_tag=$4 attest=$5 attest_tag=$6
  local attest_digest=$7 mkosi=$8 mkosi_version=$9

  case "$domain" in
    node-image) ;;
    *) die "unknown update domain: $domain" ;;
  esac
  require_sha "$confos" "--confos"
  require_release_tag "$confos_tag" "--confos-tag"
  require_sha "$attest" "--attest"
  require_release_tag "$attest_tag" "--attest-tag"
  require_digest "$attest_digest" "--attest-digest"
  require_sha "$mkosi" "--mkosi-sha"
  require_version "$mkosi_version" "--mkosi-ver"
  validate_manifest "$manifest"

  tmp_path=$(mktemp "${manifest}.tmp.XXXXXX")
  cp -p -- "$manifest" "$tmp_path"
  if [[ "$domain" == node-image ]]; then
    jq \
      --arg confos "$confos" --arg confos_tag "$confos_tag" \
      --arg attest "$attest" --arg attest_tag "$attest_tag" \
      --arg attest_digest "$attest_digest" \
      --arg mkosi "$mkosi" --arg version "$mkosi_version" '
        .builds["node-image"] = {
          confos_ref: $confos,
          confos_tag: $confos_tag,
          attestation_rs_ref: $attest,
          attestation_rs_tag: $attest_tag,
          attestation_api_digest: $attest_digest,
          mkosi_ref: $mkosi,
          mkosi_version: $version
        }
      ' "$manifest" >"$tmp_path"
  fi
  # Same pins, same manifest: compare the documents, not the bytes, so a
  # hand-formatted manifest is not rewritten for nothing.
  if jq -e -s '.[0] == .[1]' "$manifest" "$tmp_path" >/dev/null; then
    rm -f -- "$tmp_path"
    tmp_path=
    echo "no-drift"
    return
  fi
  validate_manifest "$tmp_path"
  mv -f -- "$tmp_path" "$manifest"
  tmp_path=
  echo "updated $domain"
}

require_command jq
(($# > 0)) || usage
command_name=$1
shift

manifest=
domain=
output_format=
confos_override=
confos=
confos_tag=
attest=
attest_tag=
attest_digest=
mkosi_sha=
mkosi_ver=

while (($# > 0)); do
  case "$1" in
    --manifest | --domain | --format | --confos-override | --confos | --confos-tag | --attest | --attest-tag | --attest-digest | --mkosi-sha | --mkosi-ver)
      (($# >= 2)) || usage
      case "$1" in
        --manifest) manifest=$2 ;;
        --domain) domain=$2 ;;
        --format) output_format=$2 ;;
        --confos-override) confos_override=$2 ;;
        --confos) confos=$2 ;;
        --confos-tag) confos_tag=$2 ;;
        --attest) attest=$2 ;;
        --attest-tag) attest_tag=$2 ;;
        --attest-digest) attest_digest=$2 ;;
        --mkosi-sha) mkosi_sha=$2 ;;
        --mkosi-ver) mkosi_ver=$2 ;;
      esac
      shift 2
      ;;
    *) usage ;;
  esac
done

[[ -n "$manifest" ]] || usage
case "$command_name" in
  validate)
    validate_manifest "$manifest"
    echo "valid"
    ;;
  export)
    [[ -n "$domain" && -n "$output_format" ]] || usage
    export_pins "$manifest" "$domain" "$output_format" "$confos_override"
    ;;
  update)
    [[ -n "$domain" && -n "$confos" && -n "$confos_tag" && -n "$attest" &&
      -n "$attest_tag" && -n "$attest_digest" && -n "$mkosi_sha" &&
      -n "$mkosi_ver" ]] || usage
    update_manifest \
      "$manifest" "$domain" "$confos" "$confos_tag" "$attest" "$attest_tag" \
      "$attest_digest" "$mkosi_sha" "$mkosi_ver"
    ;;
  *) usage ;;
esac
