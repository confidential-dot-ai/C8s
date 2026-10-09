#!/usr/bin/env bash
# metal backend: the single-node c8s node image a metal lane (snp-metal-e2e /
# tdx-metal-e2e) booted and attested, driven from the lane's extra-suite hook
# after its own asserts passed. A real TEE, but no shell on the node: what
# needs one (ctr, crictl) answers 77. Needs the c8s CLI on PATH.
# Interface: common.sh.

: "${KUBECONFIG:?the attested kubeconfig from the lane}"
: "${C8S_ALLOWLIST_URL:?the allowlist front door of the guest}"
: "${C8S_OPERATOR_KEY:?the operator key of the launch}"
PLATFORM="${SUITE_PLATFORM:-metal}"
# shellcheck source=common.sh
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
. "$C8S_ROOT/test/e2e/lib.sh"  # cds_measurement_args
cds_measurement_args

# Entries setup wrote, for teardown to delete.
written="${SUITE_RESULTS:-${TMPDIR:-/tmp}}/metal-backend-entries"

# shellcheck disable=SC2154  # measurement_args: set by cds_measurement_args above
al() { c8s allowlist "$@" --url "$C8S_ALLOWLIST_URL" "${measurement_args[@]}"; }

# The floor the scenarios assume. The baked floor holds neither fixture image;
# "nginx" goes on it by a signed write (`add` prints the entry's name), "rogue"
# stays off.
setup() {
    local ref
    ref="$(image_ref nginx)"
    al add "$(image_digest "$ref")" "$ref" | awk '$1 == "added" {print $2}' >> "$written"
}

teardown() {
    [ -s "$written" ] || return 0
    # shellcheck disable=SC2046  # one argument per entry
    al delete $(sort -u "$written") >/dev/null || true
    rm -f "$written"
}

node_name() {
    case "$1" in
        one) kubectl get nodes -o jsonpath='{.items[0].metadata.name}' ;;
        *) return $UNSUPPORTED ;;
    esac
}

# The registry digest, as allowlist entries pin it.
image_digest() { c8s allowlist inspect-image "$1" | awk '$1 == "digest:" {print $2}'; }

image_alias() { return $UNSUPPORTED; }

served_allowlist() { al export; }

# `apply` takes a name-keyed map of entries and lints it against the live
# document first.
allowlist_put() {
    jq -c --arg name "$1" '{($name): .}' "$2" | al apply - >/dev/null
    echo "$1" >> "$written"
}

allowlist_delete() { al delete "$1" >/dev/null 2>&1 || true; }

# The base allowlist is measured into the node image (node-guest-image/c8s/
# image-policy.yaml.in): the node's system images and c8s's components. With
# no shell on the node it is not readable, so answer from what runs under
# those entries: a digest running in the platform namespaces is in it, nothing
# else is.
base_declares() {
    local ns digest
    for ns in "$NS" kube-system; do
        for digest in $(kubectl -n "$ns" get pods -o jsonpath='{range .items[*].status.containerStatuses[*]}{.imageID}{"\n"}{end}' |
            grep -oE 'sha256:[0-9a-f]{64}' | sort -u); do
            [ "$digest" = "$2" ] && { echo yes; return; }
        done
    done
    echo no
}

# The lane's components-ready assert gates the suite; here only the node's
# readiness is rechecked.
enforcer_ready() {
    [ "$(kubectl get node "$1" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}')" = True ]
}

node_containers() { return $UNSUPPORTED; }

dispatch "$@"
