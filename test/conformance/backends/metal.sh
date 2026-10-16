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
    local pid="$(scratch)/external-hello/pid"
    [ ! -s "$pid" ] || { kill "$(cat "$pid")" 2>/dev/null; rm -f "$pid"; }
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

# The CDS Service's node port on the guest: the lane's runner reaches every
# port of the guest at the address the router's front door has, and the
# CDS's ingress policy admits its port from anywhere. Signed writes and raw
# reads go there, as kind's go through its port-forward; the router keeps
# the allowlist route. The launch bundle's key is the run's operator key; the
# token minter is built from the checkout on first use, with the Go
# toolchain that built the CLI.
guest_host() { local host="${C8S_ALLOWLIST_URL#https://}"; echo "${host%%[:/]*}"; }
cds_node_port() { cached cds-node-port kubectl -n "$NS" get svc c8s-cds -o jsonpath='{.spec.ports[0].nodePort}'; }
cds_url() {
    local port
    port="$(cds_node_port)" || return
    [ -n "$port" ] || { echo "backend: the CDS Service has no node port" >&2; return 1; }
    echo "https://$(guest_host):$port"
}
router_url() { echo "${C8S_ALLOWLIST_URL%/}"; }
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

# The same listener dialled without TLS; it is TLS-only.
cds_plain_url() { local url; url="$(cds_url)" || return; echo "${url/https:/http:}"; }

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

# A hello API on the lane's runner, outside the cluster: pods reach the
# runner's address through the launcher's address translation. It is kept
# for the run and stopped by teardown. A pod that is not injected has no
# socket to the attestation service.
EXTERNAL_HELLO_PORT=18080
external_endpoint() {
    local dir addr _
    dir="$(scratch)/external-hello"
    addr="$(hostname -I | awk '{print $1}')"
    [ -n "$addr" ] || { echo "backend: the runner has no address" >&2; return 1; }
    if [ ! -s "$dir/pid" ]; then
        mkdir -p "$dir/www"
        echo hello > "$dir/www/index.html"
        setsid python3 -m http.server -b 0.0.0.0 -d "$dir/www" "$EXTERNAL_HELLO_PORT" >"$dir/log" 2>&1 < /dev/null &
        echo $! > "$dir/pid"
        for _ in $(seq 30); do
            curl -sf --max-time 1 "http://127.0.0.1:$EXTERNAL_HELLO_PORT/" >/dev/null && break
            sleep 0.5
        done
    fi
    echo "$addr:$EXTERNAL_HELLO_PORT"
}
attestation_endpoint() { return "$UNSUPPORTED"; }

# The node image installs the router's nginx files from what `c8s node-image
# render` writes at the image's ref, which is this checkout's and the CLI's;
# rendered once per run with the Helm the image build pins. The files carry
# no image reference, so the render's required digests are placeholders.
router_nginx_conf() {
    local out="$(scratch)/node-integration"
    [ -s "$out/router-nginx/nginx.conf" ] || render_node_integration "$out" >&2 || return
    cat "$out"/router-nginx/*.conf
}

render_node_integration() {
    local out="$1" sync="$C8S_ROOT/node-guest-image/c8s/mkosi.sync" helm version sha kube platform
    local zero="sha256:0000000000000000000000000000000000000000000000000000000000000000"
    version="$(sed -n 's/^HELM_VERSION="\(.*\)"$/\1/p' "$sync")"
    sha="$(sed -n 's/^HELM_LINUX_AMD64_SHA256="\(.*\)"$/\1/p' "$sync")"
    kube="$(sed -n 's/^RKE2_VERSION="\(.*\)"$/\1/p' "$sync")"
    platform="$(mesh_platform)" || return
    helm="$(scratch)/helm"
    mkdir -p "$helm"
    curl -fsSL "https://get.helm.sh/helm-$version-linux-amd64.tar.gz" -o "$helm/helm.tgz" || return
    echo "$sha  $helm/helm.tgz" | sha256sum -c - >/dev/null || return
    tar -xzf "$helm/helm.tgz" -C "$helm" linux-amd64/helm || return
    PATH="$helm/linux-amd64:$PATH" c8s node-image render --hardware-platform "$platform" \
        --kube-version "${kube%%+*}" --image-digest "$zero" --cds-image-digest "$zero" \
        --armtls-mesh-image-digest "$zero" --output-dir "$out"
}

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
# principal, so nothing here reads a pod's files or runs in it.
pod_exec() { return "$UNSUPPORTED"; }
pod_cert_file() { return "$UNSUPPORTED"; }
requester_request() { return "$UNSUPPORTED"; }
mesh_member() { return "$UNSUPPORTED"; }
mesh_metrics() { return "$UNSUPPORTED"; }

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

# metal-dev.sh sources this file for its definitions.
[ "${BASH_SOURCE[0]}" != "$0" ] || dispatch "$@"
