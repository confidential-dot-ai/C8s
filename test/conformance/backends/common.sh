# shellcheck shell=bash
# Shared by every backend in this directory. A backend sources this file (it
# loads the kind harness lib for CURL_IMAGE, WORKLOAD_IMAGE and
# CLUSTER_HARNESS_DIR, and derives C8S_ROOT), sets PLATFORM, overrides what
# differs, and ends with `dispatch "$@"`. README.md beside this file says who
# calls these functions and how.
#
# Interface: a backend exposes these functions, each exiting 0 with its answer
# on stdout, 77 when this environment cannot express the request (a named
# skip), anything else when the harness is broken.
#   subject                          the system under test, for the run summary
#   kubeconfig                       the file every kubectl call of a run uses
#   setup / teardown                 once per run, before and after the scenarios
#   node_name <logical>              the Kubernetes node behind a scenario's node
#   image_ref <logical>              a pullable reference for a scenario's image
#   image_digest <ref>               the digest the plugin compares for ref
#   image_alias <ref> <name>         make the node resolve name to ref's bytes
#   served_allowlist                 the allowlist document CDS serves, as JSON
#   allowlist_put <name> <file>      write the entry in file under name, signed
#   allowlist_delete <name>          delete the entry; absent is not an error
#   base_declares <node> <digest>    yes/no: the node's base allowlist names digest
#   pull_interval                    how often the plugin pulls, as a Go duration
#   plugin_ready <node>              wait until the node's admission plugin is registered and ready
#   plugin_stop <node>               stop the plugin; the runtime creates no workload container
#                                    until plugin_start
#   plugin_start <node>              start the plugin again and wait until it is ready
#   cds_block / cds_unblock          make the CDS unreachable for every node's pull, and undo it
#   cds_restart                      restart the CDS and wait until it serves again
#   cds_volatile                     yes/no: a CDS restart loses the allowlist and its version
#   served_version                   the version of the allowlist CDS serves now
#   node_containers <node> <digest>  ids of the runtime's containers from digest
#   pod_manifest <name> <ns> <node> <image> <command...> [+ <image> <command...>]...
#                                    a pod manifest pinned to node, one
#                                    container per +-separated group
#   image_entrypoint <ref>           the argv the image starts with when the pod
#                                    spec overrides nothing, one word per line
#   operator_keys                    yes/no: the CDS holds an operator key
#   seed_declares <digest>           yes/no: the seed of the CDS names digest
#   write_token <operator|foreign> <method> <path> <body-file> [validity]
#                                    the Authorization header of a write token,
#                                    signed with the operator's key or with one
#                                    that is not an operator key
#   allowlist_request <method> <path> <body-file> [authorization]
#                                    send the write as given, authorization
#                                    included only when given; prints the status
#   allowlist_get [version]          read the allowlist, naming version in
#                                    If-None-Match when given; prints
#                                    "<status> <version>", then the body
#   cds_read <document> [plain]      read a document of the CDS with no client
#                                    certificate (mesh-ca, reference-values,
#                                    operator-key-set, allowlist, readiness),
#                                    over plain HTTP when asked; prints the
#                                    status, then the body
#   cds_serving_cert                 the certificate the CDS presents in the
#                                    TLS handshake, PEM
#   cds_ready                        yes/no: the CDS reports itself ready
#   cds_pins                         the launch digests the CDS was started
#                                    with, one per line
#   operator_key_set                 the operator public keys the CDS loaded at
#                                    startup, PEM
#   cds_restart_with <parameter> <value>
#                                    restart the CDS with min-ca-validity
#                                    <duration>, pins <digest> or operator-keys
#                                    none; default restores the installed
#                                    configuration
#   attestation_service_stop / attestation_service_start
#                                    the local attestation service of the
#                                    CDS's node
#   private_keys <node>              every PEM private key held outside CDS
#                                    process memory: in Kubernetes objects and
#                                    in the files of the node
#   attest_direct                    one issuance against the CDS process from
#                                    an admitted TEE; prints the chain, PEM
# node_name, image_ref, image_digest and pull_interval answer the same for a
# whole run; callers may cache them. The allowlist is state: served_allowlist
# answers for the moment of the call.
set -o pipefail

C8S_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
. "$C8S_ROOT/test/integration/cluster/lib.sh"

UNSUPPORTED=77

subject() { echo "c8s $(git -C "$C8S_ROOT" rev-parse --short HEAD) on $PLATFORM"; }

kubeconfig() { echo "$KUBECONFIG"; }

# "rogue" is the harness's curl image, which no entry declares at install;
# "nginx" is its workload image, admitted under any argv by the install seed
# (kind) or by an entry setup writes (metal). The rest are public images no
# served entry and no base allowlist names, for the scenarios that write their
# own entries; each has its own digest.
image_ref() {
    case "$1" in
        rogue) echo "docker.io/$CURL_IMAGE" ;;
        nginx) echo "docker.io/$WORKLOAD_IMAGE" ;;
        tenant-app) echo "docker.io/library/busybox:1.36.1" ;;
        job-runner) echo "docker.io/library/alpine:3.20" ;;
        model-server) echo "docker.io/library/debian:bookworm-slim" ;;
        model-loader) echo "docker.io/library/busybox:1.35.0" ;;
        *) return $UNSUPPORTED ;;
    esac
}

# The plugin's pull interval: the chart's nriImagePolicy.refresh.interval,
# which the node image bakes as the equal value (node-guest-image/c8s/
# image-policy.yaml.in, allowlist.pull.interval). The plugin exposes nothing
# about the version it holds, and containerd discards its log, so the steps
# wait this out rather than observe it.
pull_interval() { echo 5s; }

# The harness's Restricted-compatible pod, pinned to the node. Containers after
# the first are the fixture's --container groups, one shell-quoted string each.
pod_manifest() {
    local name="$1" ns="$2" node="$3" image="$4"
    shift 4
    local -a first=() extras=() group=()
    local arg first_done=0
    for arg in "$@" +; do # the trailing + flushes the last group
        if [ "$arg" != + ]; then
            group+=("$arg")
        elif [ "$first_done" = 0 ]; then
            first=("${group[@]}") first_done=1 group=()
        else
            extras+=(--container "$(printf '%q ' "${group[@]}")") group=()
        fi
    done
    python3 "$CLUSTER_HARNESS_DIR/pod-fixture.py" client "$name" "$ns" "$image" \
        --node "$node" --pull-policy IfNotPresent "${extras[@]}" -- "${first[@]}"
}

# Every plugin pulls from https://127.0.0.1:<node port of the CDS Service>
# (the chart's nriImagePolicy.allowlist.pull.url default and the node image's
# image-policy.yaml.in). Moving the Service's node port leaves nothing
# listening on the port the plugin dials, so each pull is refused at once
# rather than after its timeout, while the Service stays reachable on its
# cluster IP for the operator's writes. The port it had is kept in an
# annotation on the Service, so cds_unblock restores it from any process.
CDS_PORT_ANNOTATION=c8s-conformance/node-port

cds_block() {
    local port candidate
    port="$(kubectl -n "$NS" get svc c8s-cds -o jsonpath="{.metadata.annotations.$CDS_PORT_ANNOTATION}")"
    [ -z "$port" ] || return 0 # already blocked
    port="$(kubectl -n "$NS" get svc c8s-cds -o jsonpath='{.spec.ports[0].nodePort}')"
    [ -n "$port" ] || { echo "backend: the CDS Service has no node port" >&2; return 1; }
    kubectl -n "$NS" annotate svc c8s-cds "$CDS_PORT_ANNOTATION=$port" --overwrite >/dev/null
    for candidate in $(seq $((port + 1)) $((port + 5))); do
        kubectl -n "$NS" patch svc c8s-cds --type json \
            -p "[{\"op\":\"replace\",\"path\":\"/spec/ports/0/nodePort\",\"value\":$candidate}]" >/dev/null 2>&1 && return 0
    done
    kubectl -n "$NS" annotate svc c8s-cds "$CDS_PORT_ANNOTATION-" >/dev/null
    echo "backend: no free node port near $port" >&2
    return 1
}

cds_unblock() {
    local port
    port="$(kubectl -n "$NS" get svc c8s-cds -o jsonpath="{.metadata.annotations.$CDS_PORT_ANNOTATION}")"
    [ -n "$port" ] || return 0
    kubectl -n "$NS" patch svc c8s-cds --type json \
        -p "[{\"op\":\"replace\",\"path\":\"/spec/ports/0/nodePort\",\"value\":$port}]" >/dev/null
    kubectl -n "$NS" annotate svc c8s-cds "$CDS_PORT_ANNOTATION-" >/dev/null
}

# The CDS keeps its allowlist and version counter in its data volume; a
# restart loses both when that volume is an emptyDir (the chart's
# cds.persistence.enabled=false), and the seed is applied again.
cds_volatile() {
    if [ -n "$(kubectl -n "$NS" get deploy c8s-cds -o jsonpath='{.spec.template.spec.volumes[?(@.name=="data")].emptyDir}')" ]; then
        echo yes
    else
        echo no
    fi
}

# --- The CDS API as a caller sees it ---
# The signed path (allowlist_put, allowlist_delete) is the harness's way of
# writing; these send what a scenario says, authorization included or not,
# with curl against the CDS. A backend provides what differs:
#   cds_url        the base URL of the CDS, reachable from here
#   operator_key   the operator's private key, PEM
#   optoken_bin    the token minter built from test/integration/cluster/optoken
#   scratch        a directory kept for the run

operator_keys() {
    local url code
    url="$(cds_url)" || return
    code="$(curl -sSk -o /dev/null -w '%{http_code}' "$url/operator-keys")" || code=000
    case "$code" in
        200) echo yes ;;
        404) echo no ;;
        *) echo "backend: GET /operator-keys: HTTP $code" >&2; return 1 ;;
    esac
}

# The chart's seed ConfigMap, where the chart installed one.
seed_declares() {
    local seed
    seed="$(kubectl -n "$NS" get configmaps -o json |
        jq -r '.items[] | select(.metadata.name | endswith("-allowlist-seed")) | .data["allowlist-seed.json"] // empty')"
    [ -n "$seed" ] || return $UNSUPPORTED
    if printf '%s' "$seed" | grep -qF "$1"; then echo yes; else echo no; fi
}

# A key that is not an operator key, minted once per run.
foreign_key() {
    local key
    key="$(scratch)/foreign.key"
    [ -s "$key" ] || openssl ecparam -genkey -name prime256v1 -noout -out "$key" 2>/dev/null
    echo "$key"
}

write_token() {
    local key bin
    case "$1" in
        operator) key="$(operator_key)" || return ;;
        foreign) key="$(foreign_key)" || return ;;
        *) echo "backend: write_token: no signer '$1'" >&2; return 2 ;;
    esac
    shift
    bin="$(optoken_bin)" || return
    "$bin" "$key" "$@"
}

# Always exit 0: curl prints 000 on transport failure, and the steps assert on
# the code itself.
allowlist_request() {
    local url
    url="$(cds_url)" || return
    local -a auth=()
    [ -z "${4:-}" ] || auth=(-H "Authorization: $4")
    curl -sSk -o /dev/null -w '%{http_code}' -X "$1" -H 'Content-Type: application/json' \
        --data-binary "@$3" ${auth[@]+"${auth[@]}"} "$url$2" || true
}

allowlist_get() {
    local url headers body status
    url="$(cds_url)" || return
    headers="$(mktemp)"
    body="$(mktemp)"
    local -a match=()
    [ -z "${1:-}" ] || match=(-H "If-None-Match: W/\"$1\"")
    status="$(curl -sSk -o "$body" -D "$headers" -w '%{http_code}' ${match[@]+"${match[@]}"} "$url/allowlist")" || status=000
    echo "$status $(awk 'tolower($1) == "etag:" {gsub(/[^0-9]/, "", $2); print $2}' "$headers")"
    cat "$body"
    rm -f "$headers" "$body"
}

# --- The CDS's own documents and state ---
# A backend provides cds_plain_url, the same listener over http://, or 77.

cds_document_path() {
    case "$1" in
        mesh-ca) echo /ca ;;
        reference-values) echo /measurements ;;
        operator-key-set) echo /operator-keys ;;
        allowlist) echo /allowlist ;;
        readiness) echo /readyz ;;
        *) echo "backend: no CDS document '$1'" >&2; return 2 ;;
    esac
}

# Status 000 when nothing answered, as for a TLS-only listener dialled plain.
cds_read() {
    local url path body status
    path="$(cds_document_path "$1")" || return
    if [ "${2:-}" = plain ]; then
        url="$(cds_plain_url)" || return
    else
        url="$(cds_url)" || return
    fi
    body="$(mktemp)"
    status="$(curl -sk -o "$body" -w '%{http_code}' --max-time 20 "$url$path" 2>/dev/null)" || status=000
    echo "$status"
    cat "$body"
    rm -f "$body"
}

cds_serving_cert() {
    local url host
    url="$(cds_url)" || return
    host="${url#https://}"
    host="${host%%/*}"
    openssl s_client -connect "$host" </dev/null 2>/dev/null | openssl x509
}

cds_ready() {
    if [ "$(cds_read readiness | head -1)" = 200 ]; then echo yes; else echo no; fi
}

# dispatch <function> <args...>: an unknown name is a harness error, not a skip.
dispatch() {
    declare -F "$1" >/dev/null || { echo "backend: no function '$1'" >&2; return 2; }
    "$@"
}
