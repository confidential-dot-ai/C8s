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
# Not the router's nginx digest: the served allowlist carries the router's
# pinned entry for that one, and lint refuses an any-argv entry beside it.
NGINX_IMAGE=nginxinc/nginx-unprivileged@sha256:56b8272e43a0525f67aed68d1e0794a712d10e3e45a563e118e9a77c817e6f86  # 1.30.5-alpine
# shellcheck source=common.sh
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
. "$C8S_ROOT/test/e2e/lib.sh"  # cds_measurement_args
cds_measurement_args

# Entries setup wrote, for teardown to delete.
written="${SUITE_RESULTS:-${TMPDIR:-/tmp}}/metal-backend-entries"

# shellcheck disable=SC2154  # measurement_args: set by cds_measurement_args above
# The router admits one write a second per client (curl_paced): a 429 is
# waited out. Input comes from a file, never stdin, so a retry can resend it.
al() {
    local err rc _
    err="$(mktemp)"
    for _ in $(seq 10); do
        c8s allowlist "$@" --url "$C8S_ALLOWLIST_URL" "${measurement_args[@]}" 2>"$err" && rc=0 || rc=$?
        if [ "$rc" -eq 0 ] || ! grep -q 'server returned 429' "$err"; then break; fi
        sleep 1
    done
    cat "$err" >&2
    rm -f "$err"
    return "$rc"
}

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

# The node image's own c8s image is not pullable from the harness host.
injected_image() { return $UNSUPPORTED; }

# The node image keeps its state on encrypted scratch (docs/node-image.md).
scratch_encrypted() { echo yes; }

# The lane's allowlist URL is the router on the guest's public address: the
# c8s CLI's signed writes and raw reads reach the CDS through its built-in
# allowlist route, which forwards the /allowlist routes unchanged. The
# operator's credential may neither exec, port-forward nor write in $NS, so
# that route is the harness's only way to the CDS: its other documents, its
# own serving certificate and its Service answer 77 below. The launch
# bundle's key is the run's operator key; the token minter is built from the
# checkout on first use, with the Go toolchain that built the CLI.
cds_url() { echo "${C8S_ALLOWLIST_URL%/}"; }
# The route relays the /allowlist routes alone; the CDS's others are out of
# reach.
cds_request() {
    case "$2" in
        /allowlist | /allowlist/*) http_request "$(cds_url)" "$@" ;;
        *) return "$UNSUPPORTED" ;;
    esac
}
router_url() { echo "${C8S_ALLOWLIST_URL%/}"; }
cds_document_path() {
    case "$1" in
        allowlist) echo /allowlist ;;
        *) return "$UNSUPPORTED" ;;
    esac
}
cds_serving_cert() { return "$UNSUPPORTED"; }
# No node shell, so the plugin's health socket is out of reach.
applied_version() { return "$UNSUPPORTED"; }
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

# The node image's confos-pod-exec policy closes pod exec for every
# principal, so a command reaches a pod through its own annotations instead
# (agent_run below).
pod_exec() { echo agent; }

# A pod whose first container runs an argv the harness chose (the steps mark
# it c8s-conformance/harness-argv) runs an agent there, in place of the
# placeholder `sleep 3600` or beside anything else: it reads two annotations
# from a downward-API volume, which the kubelet rewrites when the pod is
# patched, runs the command they carry and prints its combined output and
# status to the container log.
AGENT=c8s-conformance/agent
AGENT_DIR=/run/c8s-conformance-agent
# shellcheck disable=SC2016  # expands in the pod
AGENT_SCRIPT='last=0; while :; do s=$(cat '"$AGENT_DIR"'/seq 2>/dev/null); if [ -n "$s" ] && [ "$s" != 0 ] && [ "$s" != "$last" ]; then last=$s; base64 -d '"$AGENT_DIR"'/cmd > /tmp/.agent-cmd 2>/dev/null; sh /tmp/.agent-cmd > /tmp/.agent-out 2>&1; rc=$?; echo "agent $s $rc $(base64 < /tmp/.agent-out | tr -d "\n")"; fi; sleep 1; done'

pod_manifest() { render_pod --sysctl "$PING_SYSCTL" "$@" | agent_wrap; }

requester_manifest() {
    local image
    image="$(image_ref requester)" || return
    render_pod --annotation confidential.ai/c8s-injected=true --annotation c8s-conformance/harness-argv=yes \
        --container-name "$REQUESTER_CONTAINER" --supplemental-group 65532 \
        -- "$1" "$2" "$3" "$image" sleep 3600 | agent_wrap
}

# Sent by curl in the requester through its agent; the body travels in the
# command, as the agent has no stdin.
requester_request() {
    local ns="$1" pod="$2" method="$3" url="$4" body="${5:-}" socket="${6:-}" resp script
    local -a opts=(-sk --max-time 30 -X "$method" -w '\n%{http_code}')
    [ -z "$socket" ] || opts+=(--unix-socket "$socket")
    if [ -n "$body" ]; then
        opts+=(-H 'Content-Type: application/json' --data-binary @-)
        script="echo $(base64 < "$body" | tr -d '\n') | base64 -d | curl $(shq "${opts[@]}" "$url")"
    else
        script="curl $(shq "${opts[@]}" "$url")"
    fi
    local rc=0
    resp="$(agent_run "$ns" "$pod" "$REQUESTER_CONTAINER" "$script")" || rc=$?
    [ "$rc" != "$UNSUPPORTED" ] || return "$UNSUPPORTED"
    resp="$(printf '%s' "$resp" | base64 -d)"
    # curl exits non-zero only when no response came back.
    if [ "$rc" != 0 ]; then
        echo "backend: the requester's curl ($((${#script} / 1024)) KiB of script) exited $rc: $resp" >&2
        return 1
    fi
    echo "${resp##*$'\n'}"
    printf '%s\n' "${resp%$'\n'*}"
}

# shq <word...>: each word single-quoted for a POSIX sh.
shq() { local w; for w in "$@"; do printf "'%s' " "${w//\'/\'\\\'\'}"; done; }

agent_wrap() {
    jq -c --arg a "$AGENT" --arg dir "$AGENT_DIR" --arg script "$AGENT_SCRIPT" --arg q "'" '
        if .metadata.annotations["c8s-conformance/harness-argv"] == "yes" then
            .metadata.annotations += {($a): "yes", ($a + "-seq"): "0", ($a + "-cmd"): ""}
            | .spec.containers[0].command |= (if . == ["sleep", "3600"] then ["sh", "-c", $script]
                else ["sh", "-c", "(" + (map(@sh) | join(" ")) + ") & " + $script] end)
            | .spec.containers[0].volumeMounts += [{name: "c8s-conformance-agent", mountPath: $dir, readOnly: true}]
            | .spec.volumes += [{name: "c8s-conformance-agent", downwardAPI: {items: [
                {path: "seq", fieldRef: {fieldPath: ("metadata.annotations[" + $q + $a + "-seq" + $q + "]")}},
                {path: "cmd", fieldRef: {fieldPath: ("metadata.annotations[" + $q + $a + "-cmd" + $q + "]")}}]}}]
        else . end'
}

# agent_run <ns> <pod> <container> <script>: the sh script's combined output
# as base64, and its status as ours. The agent runs in the first
# container alone, so another named container answers 77, as does a pod
# without the agent; 1 when the agent has not answered in a minute.
agent_run() {
    local ns="$1" pod="$2" want="$3" script="$4" pod_json seq line container rc out deadline patch
    pod_json="$(kubectl -n "$ns" get pod "$pod" -o json 2>/dev/null)" || return "$UNSUPPORTED"
    [ "$(jq -r --arg a "$AGENT" '.metadata.annotations[$a] // empty' <<<"$pod_json")" = yes ] || return "$UNSUPPORTED"
    container="$(jq -r '.spec.containers[0].name' <<<"$pod_json")"
    [ -z "$want" ] || [ "$want" = "$container" ] || return "$UNSUPPORTED"
    seq="$(date +%s%N)"
    # Through a patch file: a request body makes the script larger than one
    # command-line argument may be (128 KiB on Linux).
    patch="$(mktemp)"
    printf '%s' "$script" | base64 | tr -d '\n' |
        jq -Rs --arg a "$AGENT" --arg seq "$seq" '{metadata: {annotations: {($a + "-cmd"): ., ($a + "-seq"): $seq}}}' > "$patch"
    rc=0
    kubectl -n "$ns" patch pod "$pod" --type merge --patch-file "$patch" >/dev/null || rc=$?
    rm -f "$patch"
    [ "$rc" = 0 ] || return "$rc"
    deadline=$(($(date +%s) + 60))
    until line="$(kubectl -n "$ns" logs "$pod" -c "$container" 2>/dev/null | grep "^agent $seq " | tail -1)" && [ -n "$line" ]; do
        [ "$(date +%s)" -lt "$deadline" ] || { echo "backend: the agent in $ns/$pod did not answer within 60s" >&2; return 1; }
        sleep 1
    done
    read -r _ _ rc out <<<"$line"
    printf '%s' "${out:-}"
    return "$rc"
}

# agent_exec <ns> <pod> <script>: agent_run in the first container, its
# output decoded.
agent_exec() {
    local out rc=0
    out="$(agent_run "$1" "$2" "" "$3")" || rc=$?
    printf '%s' "$out" | base64 -d
    return "$rc"
}

# Nothing while the file is absent or the agent does not answer yet, as
# pod_cert_file answers elsewhere; 77 for a pod without the agent.
pod_cert_file() {
    local out rc=0
    out="$(agent_exec "$1" "$2" "cat '$CERT_VOLUME_PATH/$3'" 2>/dev/null)" || rc=$?
    case "$rc" in
        0) printf '%s\n' "$out" ;;
        "$UNSUPPORTED") return "$UNSUPPORTED" ;;
    esac
}
mesh_member() { return "$UNSUPPORTED"; }

# No exec into a kept scraper: each scrape is a pod of its own whose log is
# the scrape, admitted by the scraper's entry, which teardown deletes.
mesh_metrics() {
    local addr port image digest entry name phase body _
    addr="$(cached "node-ipv4-$1" node_address "$1" ipv4)" || return
    port="$(cached mesh-health-port mesh_arg health-port)"
    port="${port:-15021}"
    image="$(image_ref requester)" || return
    entry="$(scratch)/cache-mesh-scrape-entry"
    if [ ! -e "$entry" ]; then
        kubectl create namespace "$MESH_SCRAPER_NS" >/dev/null 2>&1 || true
        digest="$(image_digest "$image")" || return
        any_workload "$digest" "$image" > "$entry.json"
        allowlist_put "$MESH_SCRAPER" "$entry.json" || return
        touch "$entry"
    fi
    name="mesh-scrape-$(date +%s%N | tail -c 10)"
    render_pod -- "$name" "$MESH_SCRAPER_NS" "$(node_name one)" "$image" \
        curl -sf --max-time 10 "http://$addr:$port/metrics" | kubectl apply -f - >/dev/null || return
    for _ in $(seq 90); do
        phase="$(kubectl -n "$MESH_SCRAPER_NS" get pod "$name" -o jsonpath='{.status.phase}' 2>/dev/null)"
        case "$phase" in Succeeded | Failed) break ;; esac
        sleep 1
    done
    body="$(kubectl -n "$MESH_SCRAPER_NS" logs "$name" 2>/dev/null)"
    kubectl -n "$MESH_SCRAPER_NS" delete pod "$name" --wait=false >/dev/null 2>&1
    [ "$phase" = Succeeded ] || { echo "backend: no scrape of $addr:$port (pod $name: ${phase:-no phase})" >&2; return 1; }
    printf '%s\n' "$body"
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

image_env() {
    command -v crane >/dev/null || return $UNSUPPORTED
    crane config "$1" | jq -r '.config | (.Env // [])[]'
}

# Signed writes through the route, as kind's are, not `apply`: that lints
# against the live document and refuses an entry a broader one shadows,
# which the CDS accepts and scenarios write on purpose.
allowlist_write() {
    local method="$1" path="/allowlist/workloads/$2" body="$3" token code
    token="$(write_token operator "$method" "$path" "$body")" || return
    code="$(router_request "$method" "$path" "$body" "$token" | head -1)"
    case "$code" in
        204) ;;
        404) [ "$method" = DELETE ] || return 1 ;;
        *) echo "backend: $method $path: HTTP $code" >&2; return 1 ;;
    esac
}
allowlist_put() { allowlist_write PUT "$1" "$2"; }
allowlist_delete() { allowlist_write DELETE "$1" /dev/null; }

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


dispatch "$@"
