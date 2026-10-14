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

teardown_backend() {
    [ -s "$written" ] || return 0
    # shellcheck disable=SC2046  # one argument per entry
    al delete $(sort -u "$written") >/dev/null || true
    rm -f "$written"
}

# The lane's one node, not a Node object a scenario wrote (the steps label
# those conformance.c8s/ghost).
node_name() {
    case "$1" in
        one) kubectl get nodes -l '!conformance.c8s/ghost' -o jsonpath='{.items[0].metadata.name}' ;;
        *) return $UNSUPPORTED ;;
    esac
}

# The registry digest, as allowlist entries pin it.
image_digest() { c8s allowlist inspect-image "$1" | awk '$1 == "digest:" {print $2}'; }

image_alias() { return $UNSUPPORTED; }

served_allowlist() { al export; }

# The lane's allowlist URL is the router on the guest's public address: the
# c8s CLI's signed writes and raw reads reach the CDS through its built-in
# allowlist route, which forwards the /allowlist routes unchanged. The
# operator's credential may neither exec, port-forward nor write in $NS, so
# that route is the harness's only way to the CDS: its other documents, its
# own serving certificate and its Service answer 77 below. The launch
# bundle's key is the run's operator key; the token minter is built from the
# checkout on first use, with the Go toolchain that built the CLI.
cds_url() { echo "${C8S_ALLOWLIST_URL%/}"; }
router_url() { echo "${C8S_ALLOWLIST_URL%/}"; }
cds_document_path() {
    case "$1" in
        allowlist) echo /allowlist ;;
        *) return "$UNSUPPORTED" ;;
    esac
}
cds_serving_cert() { return "$UNSUPPORTED"; }
cds_block() { return "$UNSUPPORTED"; }
cds_unblock() { return "$UNSUPPORTED"; }
cds_relay_block() { return "$UNSUPPORTED"; }
cds_relay_unblock() { return "$UNSUPPORTED"; }
# The lane started the CDS pinning the launch bundle's key, the one
# operator_key names.
operator_keys() { echo yes; }
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

cds_plain_url() { return "$UNSUPPORTED"; }

# The pins the lane started the CDS with: a launch digest, or those of its
# policy file.
cds_pins() {
    if [ -n "${C8S_MEASUREMENTS:-}" ]; then
        printf '%s\n' "$C8S_MEASUREMENTS" | tr ',' '\n'
    elif [ -n "${C8S_MEASUREMENTS_CONFIG:-}" ]; then
        jq -r '.measurements[] | .measurement // .mrtd // empty' "$C8S_MEASUREMENTS_CONFIG"
    else
        echo "backend: neither C8S_MEASUREMENTS nor C8S_MEASUREMENTS_CONFIG names the CDS's pins" >&2
        return 1
    fi
}

# Reconfiguring or stopping node services, and searching the node, need a
# shell on it; an issuance from the harness host needs a TEE it has not.
cds_restart_with() { return "$UNSUPPORTED"; }
attestation_service_stop() { return "$UNSUPPORTED"; }
attestation_service_start() { return "$UNSUPPORTED"; }
private_keys() { return "$UNSUPPORTED"; }
attest_direct() { return "$UNSUPPORTED"; }

# The lane pins the node's own measurement, so its evidence satisfies them.
mesh_pins_satisfied() { echo yes; }

# No address outside the cluster answers for the lane, and a pod that is not
# injected has no socket to the attestation service.
external_endpoint() { return "$UNSUPPORTED"; }
attestation_endpoint() { return "$UNSUPPORTED"; }

# The node's local attestation service, over the socket the plugin binds into
# the requester (the webhook rebases a unix:// attestation-api URL under
# that directory for the requesters it injects). A chosen launch digest
# would need a second TEE.
attestation_socket() {
    local url
    url="$(operator_arg attestation-api-url)"
    case "$url" in
        unix://*) echo "/run/c8s/workload-claims/$(basename "${url#unix://}")" ;;
        *) return "$UNSUPPORTED" ;;
    esac
}

evidence() {
    [ -z "${4:-}" ] || return "$UNSUPPORTED"
    local socket body out
    socket="$(attestation_socket)" || return
    body="$(mktemp)"
    python3 -c 'import base64, json, sys; print(json.dumps({"report_data": base64.b64encode(bytes.fromhex(sys.argv[1])).decode()}))' "$3" >"$body"
    out="$(requester_request "$1" "$2" POST http://localhost/attest "$body" "$socket")"
    rm -f "$body"
    [ "$(head -1 <<<"$out")" = 200 ] || { echo "backend: attestation service: $out" >&2; return 1; }
    tail -n +2 <<<"$out"
}

# Real evidence with one byte of the signed report body changed: an SNP
# report's launch measurement. Other evidence shapes are not edited here.
evidence_unsigned() {
    local env
    env="$(evidence "$1" "$2" "$3")" || return
    python3 - "$env" <<'PYEOF'
import base64, json, sys
env = json.loads(sys.argv[1])
try:
    report = bytearray(base64.b64decode(env["evidence"]["attestation_report"]))
except (KeyError, TypeError):
    sys.exit(77)
report[0x90] ^= 0xFF
env["evidence"]["attestation_report"] = base64.b64encode(bytes(report)).decode()
print(json.dumps(env))
PYEOF
}

# No node shell: the certificate volume is read through a running container
# of the pod, the named one when given, else the first of the scenario's own
# (the webhook mounts the volume into every container, its own included, but
# those are distroless). Nothing while no such container runs yet.
pod_cert_file() {
    local container="${4:-}"
    [ -n "$container" ] || container="$(kubectl -n "$1" get pod "$2" -o json | jq -r '
        [((.status.initContainerStatuses // []) + (.status.containerStatuses // []))[] | select(.state.running) | .name] as $running
        | [((.spec.initContainers // []) + .spec.containers)[] | .name | select((startswith("c8s-") | not) and IN($running[]))][0] // empty')" || return
    [ -n "$container" ] || return 0
    pod_cert_file_in "$1" "$2" "$container" "$3"
}

pod_sandbox_id() { return "$UNSUPPORTED"; }

# The operator's verifier on a saved leaf: 0 accepts, 2 rejects on a verdict;
# anything else means it could not judge.
relying_party() {
    local leaf="$1" ca="$2" rc=0
    shift 2
    c8s verify --from-file "$leaf" --mesh-ca "$ca" "${measurement_args[@]}" "$@" >/dev/null 2>&1 || rc=$?
    case "$rc" in
        0) echo accepts ;;
        2) echo rejects ;;
        *) echo "backend: c8s verify exited $rc" >&2; return 1 ;;
    esac
}

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
# node-guest-image/c8s/image-policy.yaml.in. c8s's own component entries,
# which boot staging merges in, pin each image to its component's entrypoint,
# so they declare no image for a container of the scenario's.
base_declares() {
    if grep -qF "$2" "$C8S_ROOT/node-guest-image/c8s/image-policy.yaml.in"; then echo yes; else echo no; fi
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
node_refuses() { return "$UNSUPPORTED"; }
plugin_stop() { return $UNSUPPORTED; }
plugin_start() { return $UNSUPPORTED; }
cds_restart() { return $UNSUPPORTED; }

served_version() { al list | awk '$1 == "version" {sub(/:$/, "", $2); print $2; exit}'; }

dispatch "$@"
