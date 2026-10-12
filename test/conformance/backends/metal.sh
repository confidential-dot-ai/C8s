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

# The served allowlist the scenarios assume. The base allowlist names neither
# fixture image; "nginx" gets an any-argv entry by a signed write (`add`
# prints the entry's name), "rogue" gets none.
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

# The allowlist front door of the guest is the CDS's own listener, which the
# c8s CLI's signed writes and raw reads go through. The launch bundle's key is
# the run's operator key; the token minter is built from the checkout on
# first use, with the Go toolchain that built the CLI.
cds_url() { echo "$C8S_ALLOWLIST_URL"; }
operator_key() { echo "$C8S_OPERATOR_KEY"; }
scratch() { echo "${SUITE_RESULTS:-${TMPDIR:-/tmp}}"; }
optoken_bin() {
    local bin
    bin="$(scratch)/optoken"
    if [ ! -x "$bin" ]; then
        command -v go >/dev/null || return $UNSUPPORTED
        go build -C "$C8S_ROOT" -o "$bin" ./test/integration/cluster/optoken >&2 || return 1
    fi
    echo "$bin"
}

# Whether the front door is the CDS listener itself is the lane's to know;
# a plain-HTTP probe of something else would prove nothing.
cds_plain_url() { return "$UNSUPPORTED"; }

# The pins the lane started the CDS with: a launch digest, or those of its
# policy file.
cds_pins() {
    if [ -n "${C8S_MEASUREMENTS:-}" ]; then
        printf '%s\n' "$C8S_MEASUREMENTS" | tr ',' '\n'
    else
        jq -r '.measurements[].measurement // empty' "$C8S_MEASUREMENTS_CONFIG"
    fi
}

operator_key_set() { openssl ec -in "$C8S_OPERATOR_KEY" -pubout 2>/dev/null; }

# Reconfiguring or stopping node services, and searching the node, need a
# shell on it; an issuance from the harness host needs a TEE it has not.
cds_restart_with() { return "$UNSUPPORTED"; }
attestation_service_stop() { return "$UNSUPPORTED"; }
attestation_service_start() { return "$UNSUPPORTED"; }
private_keys() { return "$UNSUPPORTED"; }
attest_direct() { return "$UNSUPPORTED"; }

# From the registry, with the crane the lane installs; no node shell.
image_entrypoint() {
    command -v crane >/dev/null || return $UNSUPPORTED
    crane config "$1" | jq -r '.config | ((.Entrypoint // []) + (.Cmd // []))[]'
}

# `apply` takes a name-keyed map of entries and lints it against the live
# document first.
allowlist_put() { jq -c --arg name "$1" '{($name): .}' "$2" | al apply - >/dev/null; }

allowlist_delete() { al delete "$1" >/dev/null 2>&1 || true; }

# The base allowlist is measured into the node image and not readable without
# a shell, so answer from what it was built from: the system images pinned in
# node-guest-image/c8s/image-policy.yaml.in, plus c8s's own component entries,
# which boot staging merges in and which are the images running in $NS.
base_declares() {
    if grep -qF "$2" "$C8S_ROOT/node-guest-image/c8s/image-policy.yaml.in" ||
        kubectl -n "$NS" get pods -o jsonpath='{.items[*].status.containerStatuses[*].imageID}' | grep -qF "$2"; then
        echo yes
    else
        echo no
    fi
}

# The lane's components-ready assert gates the suite; here only the node's
# readiness is rechecked.
plugin_ready() {
    [ "$(kubectl get node "$1" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}')" = True ]
}

node_containers() { return $UNSUPPORTED; }

# No shell on the node, so its plugin cannot be stopped or started; and
# without a plugin start the plugin would ignore every allowlist a restarted
# CDS serves (its versions start over), so the CDS stays up too.
plugin_stop() { return $UNSUPPORTED; }
plugin_start() { return $UNSUPPORTED; }
cds_restart() { return $UNSUPPORTED; }

served_version() { al list | awk '$1 == "version" {sub(/:$/, "", $2); print $2; exit}'; }

dispatch "$@"
