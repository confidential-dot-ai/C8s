#!/usr/bin/env bash
set -euo pipefail

[[ $# == 1 ]] || { echo "usage: build-gate-images.sh OUTPUT_TAR" >&2; exit 2; }
output=$1
ref=$(git rev-parse HEAD)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/layouts"

build_core_image() {
    local image=$1 dockerfile=$2 layout="$work/layouts/$1" digest
    docker buildx build --platform linux/amd64 --provenance=false \
        --file "$dockerfile" \
        --tag "ghcr.io/confidential-dot-ai/$image:$ref" \
        --output "type=oci,dest=$work/$image.tar" .
    mkdir -p "$layout"
    tar -xf "$work/$image.tar" -C "$layout"
    digest=$(jq -er '.manifests | if length == 1 then .[0].digest else error("expected one image") end' "$layout/index.json")
    oras tag --oci-layout "$layout@$digest" "$ref"
    oras manifest fetch --oci-layout --descriptor "$layout:$ref" \
        | jq -e --arg digest "$digest" '.digest == $digest' >/dev/null
}

build_core_image c8s-operator cmd/c8s/Dockerfile
build_core_image cds cmd/cds/Dockerfile
build_core_image armtls-mesh cmd/armtls-mesh/Dockerfile
build_core_image c8s-router cmd/c8s-router/Dockerfile

tar -cf "$output" -C "$work/layouts" .
