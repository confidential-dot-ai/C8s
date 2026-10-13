#!/usr/bin/env bash
# kind backend: the single-node cluster the kind harness leaves up with
#   C8S_IT_KEEP=1 C8S_IT_SETUP_ONLY=1 C8S_IT_WORKDIR=... test/integration/cluster/run.sh
# Everything below delegates to that harness's lib.sh. No TEE: attestation is
# mocked, so a scenario that needs hardware evidence must not pick this backend.
# Interface: common.sh.

: "${C8S_IT_WORKDIR:?the WORKDIR the kept kind cluster wrote}"
PLATFORM="kind (mock attestation)"
# shellcheck source=common.sh
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
# shellcheck disable=SC1091  # written by the harness at run time
. "$C8S_IT_WORKDIR/env"

# The served allowlist the scenarios assume: "nginx" admitted under any argv.
# The install seed admits that digest only under its entrypoint (it is the
# router's nginx), so the entry is the backend's to write, as on metal; the
# shape is the one `c8s allowlist add` writes.
nginx_entry=conformance-nginx
setup() {
    local ref digest entry
    ref="$(image_ref nginx)"
    digest="$(image_digest "$ref")"
    entry="$(mktemp)"
    jq -nc --arg digest "$digest" --arg image "$ref" \
        '{label: $image, containers: [{digest: $digest, image: $image, command: {policy: "any"}, args: {policy: "any"}, env: {policy: "any"}, mounts: {policy: "any"}}]}' \
        > "$entry"
    allowlist_put "$nginx_entry" "$entry"
    rm -f "$entry"
}

# Each function runs in its own process, so the CDS port-forward lib.sh shares
# through WORKDIR outlives the call that opened it.
teardown() {
    allowlist_delete "$nginx_entry" || true
    cds_pf_stop
}

node_name() {
    case "$1" in
        one) echo "$NODE" ;;
        *) return $UNSUPPORTED ;;
    esac
}

store_digest() { store_digests | awk -F'\t' -v ref="$1" '$2 == ref {print $1; exit}'; }

# The digest the node's store holds for ref, pulling only when it has none.
image_digest() {
    local digest
    digest="$(store_digest "$1")"
    if [ -z "$digest" ]; then
        node_exec ctr -n k8s.io images pull "$1" >/dev/null
        digest="$(store_digest "$1")"
    fi
    echo "$digest"
}

image_alias() {
    node_exec ctr -n k8s.io images pull "$1" >/dev/null
    node_exec ctr -n k8s.io images tag --force "$1" "$2" >/dev/null
}

# The CDS through the port-forward lib.sh shares; the harness's operator key
# and token minter beside it.
cds_url() { cds_pf_start && echo "https://127.0.0.1:$CDS_LOCAL_PORT"; }
operator_key() { echo "$WORKDIR/operator.key"; }
optoken_bin() { echo "$WORKDIR/optoken"; }
scratch() { echo "$WORKDIR"; }

served_allowlist() { curl -sSfk "$(cds_url)/allowlist"; }

# The same forward dialled without TLS; the listener is TLS-only.
cds_plain_url() { local url; url="$(cds_url)" || return; echo "${url/https:/http:}"; }
cds_pins() { echo "$MOCK_MEASUREMENT"; }

CDS_SELECTOR=app.kubernetes.io/name=c8s-operator,app.kubernetes.io/component=cds
CDS_ARGS_ANNOTATION=c8s-conformance/cds-args

# The CDS container's args are edited in place; the installed ones are kept
# in an annotation on the Deployment, so default restores them from any
# process. A change applies on top of the running args, so two in one
# scenario compose; one that changes nothing needs no new pod. The
# Deployment's strategy is Recreate: the old pod goes before the new one
# comes, and a pod that never becomes ready is still the only one, so a
# reconfigured CDS is waited for as a running pod answering /healthz, not as
# a completed rollout.
cds_restart_with() {
    local state installed current args annotation pods
    state="$(kubectl -n "$NS" get deploy c8s-cds -o json | jq -c --arg a "$CDS_ARGS_ANNOTATION" \
        '{installed: (.metadata.annotations[$a] // ""), current: (.spec.template.spec.containers[] | select(.name == "cds") | .args)}')"
    installed="$(jq -r .installed <<<"$state")"
    current="$(jq -c .current <<<"$state")"
    if [ -z "$installed" ]; then
        [ "$1" != default ] || return 0 # nothing was changed
        installed="$current"
    fi
    local flag=
    case "$1" in
        default) args="$installed" ;;
        min-ca-validity) flag=--min-ca-validity ;;
        pins) flag=--measurements ;;
        operator-keys) flag=--operator-keys ;;
        san-validation) flag=--san-validation ;;
        inventory-cidr) flag=--sandbox-inventory-cidr ;;
        *) echo "backend: cds_restart_with: no parameter '$1'" >&2; return 2 ;;
    esac
    # A change applies on top of the running args, so two in one scenario
    # compose; one that changes nothing needs no new pod.
    if [ "$2" = none ]; then
        args="$(cds_arg_set "$current" "$flag")"
    elif [ -n "$flag" ]; then
        args="$(cds_arg_set "$current" "$flag" "$2")"
    fi
    # The annotation travels with the patch: set while the args differ from
    # the installed ones, gone once they are back.
    if [ "$1" = default ]; then
        annotation="{\"$CDS_ARGS_ANNOTATION\":null}"
    else
        annotation="$(jq -c --arg a "$CDS_ARGS_ANNOTATION" --arg v "$installed" '{($a): $v}' <<<'{}')"
    fi
    if [ "$(jq -c . <<<"$args")" = "$current" ]; then
        [ "$1" != default ] || kubectl -n "$NS" patch deploy c8s-cds --type strategic \
            -p "{\"metadata\":{\"annotations\":$annotation}}" >/dev/null
        return 0
    fi
    pods="$(kubectl -n "$NS" get pods -l "$CDS_SELECTOR" -o jsonpath='{.items[*].metadata.uid}')"
    cds_pf_stop
    kubectl -n "$NS" patch deploy c8s-cds --type strategic \
        -p "{\"metadata\":{\"annotations\":$annotation},\"spec\":{\"template\":{\"spec\":{\"containers\":[{\"name\":\"cds\",\"args\":$args}]}}}}" >/dev/null
    if [ "$1" = default ]; then
        kubectl -n "$NS" rollout status deploy/c8s-cds --timeout=180s >/dev/null
    else
        cds_await_running "$pods"
    fi
}

# The args JSON with --<flag>= replaced by --<flag>=<value>, or removed when
# no value is given.
cds_arg_set() {
    local flag="$2="
    if [ $# -ge 3 ]; then
        jq -c --arg p "$flag" --arg v "$flag$3" 'map(select(startswith($p) | not)) + [$v]' <<<"$1"
    else
        jq -c --arg p "$flag" 'map(select(startswith($p) | not))' <<<"$1"
    fi
}

# Wait for the one CDS pod that is none of the given UIDs (the pods before
# the change) to run and answer /healthz through the forward, then for the
# Service to route to it: that takes its readiness probe, which runs some
# seconds after the pod does. A CDS that reports itself not ready
# (min-ca-validity) never joins the Service, and is not waited for.
cds_await_running() {
    local deadline=$(($(date +%s) + 180)) pods uid phase
    while :; do
        pods="$(kubectl -n "$NS" get pods -l "$CDS_SELECTOR" -o jsonpath='{range .items[*]}{.metadata.uid} {.status.phase}{"\n"}{end}')"
        read -r uid phase <<<"$pods"
        if [ "$(printf '%s\n' "$pods" | grep -c .)" -eq 1 ] && [[ " $1 " != *" $uid "* ]] && [ "$phase" = Running ]; then
            cds_pf_start
            break
        fi
        [ "$(date +%s)" -lt "$deadline" ] || { echo "backend: the reconfigured CDS is not running: $pods" >&2; return 1; }
        sleep 2
    done
    while [ "$(curl -sk -o /dev/null -w '%{http_code}' "https://127.0.0.1:$CDS_LOCAL_PORT/readyz")" = 200 ]; do
        [ -z "$(kubectl -n "$NS" get endpoints c8s-cds -o jsonpath='{.subsets[*].addresses[*].ip}')" ] || return 0
        [ "$(date +%s)" -lt "$deadline" ] || { echo "backend: the Service does not route to the ready CDS" >&2; return 1; }
        sleep 2
    done
}

# The mock attestation-api is the local attestation service of every
# component here, the CDS's readiness check included.
attestation_service_stop() {
    kubectl -n "$MOCK_ATTESTATION_NS" scale "deploy/$MOCK_ATTESTATION_NAME" --replicas=0 >/dev/null
    kubectl -n "$MOCK_ATTESTATION_NS" wait --for=delete pod -l "app=$MOCK_ATTESTATION_NAME" --timeout=120s >/dev/null 2>&1 || true
}

attestation_service_start() {
    kubectl -n "$MOCK_ATTESTATION_NS" scale "deploy/$MOCK_ATTESTATION_NAME" --replicas=1 >/dev/null
    kubectl -n "$MOCK_ATTESTATION_NS" rollout status "deploy/$MOCK_ATTESTATION_NAME" --timeout=180s >/dev/null
}

# PEM private keys outside CDS process memory: in the Secrets and ConfigMaps
# of every namespace, and in the files of the node. The files are emitted
# as they are, binary ones included, and the reader picks the PEM blocks
# out of them. "Every file on the node" is the directories where
# configuration, state and the CDS container's root filesystem and volumes
# live, which a scan of the whole overlay would only add time to; /proc,
# /sys and /dev are not files.
private_keys() {
    kubectl get secrets,configmaps -A -o json |
        jq -r '.items[] | (.data // {})[] as $v | if .kind == "Secret" then ($v | @base64d) else $v end'
    # shellcheck disable=SC2016  # expands on the node
    node_exec sh -c '
        cds="$(crictl ps -q --name "^cds$" | head -1)"
        [ -n "$cds" ] || { echo "backend: no cds container on the node" >&2; exit 1; }
        grep -rla -e "PRIVATE KEY-----" "$@" "/run/containerd/io.containerd.runtime.v2.task/k8s.io/$cds/rootfs" 2>/dev/null | xargs -r cat' _ \
        /etc /run /root /opt /tmp /var/lib/kubelet
}

# One issuance from this host, with the CLI the harness built: the mock
# admits it like any requester, and the CSR carries a DNS SAN the CDS's
# Service pattern admits and no IP SAN (the source address the CDS sees is
# the forward's).
attest_direct() {
    local bin="$C8S_ROOT/build/c8s"
    [ -x "$bin" ] || make -C "$C8S_ROOT" build-c8s >&2 || return 1
    "$bin" get-cert --cds-url "$(cds_url)" --attestation-api-url "$(mock_attestation_url)" \
        --cds-measurements "$MOCK_MEASUREMENT" --san "requester.$NS.svc" 2>/dev/null
}

# The mock issues a version-2 SNP report over any report data, with an
# all-zero launch measurement (the pin the CDS was installed with) and no
# signature anyone checks. Evidence for another launch digest is the same
# report with those bytes set; the mock's verifier reads the digest from the
# report it is shown.
evidence() {
    python3 - "$(mock_attestation_url)" "$3" "${4:-}" <<'PYEOF'
import base64, json, sys, urllib.request
url, report_data, digest = sys.argv[1:4]
if not digest:
    body = json.dumps({"report_data": base64.b64encode(bytes.fromhex(report_data)).decode()}).encode()
    req = urllib.request.Request(url + "/attest", body, {"Content-Type": "application/json"})
    sys.stdout.write(urllib.request.urlopen(req, timeout=20).read().decode())
    sys.exit()
report = bytearray(1184)
report[0] = 0x02    # report version 2
report[0x0A] = 0x03 # SMT-allowed policy
rd = bytes.fromhex(report_data)
report[0x50:0x50 + len(rd)] = rd
d = bytes.fromhex(digest)
report[0x90:0x90 + len(d)] = d
print(json.dumps({"platform": "snp", "evidence": {"attestation_report": base64.b64encode(bytes(report)).decode()}}))
PYEOF
}

# The mock reports every signature valid, so nothing here is unsigned; and
# its evidence verifies nowhere but at the mock, so no verifier on this host
# can act as a relying party.
evidence_unsigned() { return "$UNSUPPORTED"; }
relying_party() { return "$UNSUPPORTED"; }

pod_uid() { kubectl -n "$1" get pod "$2" -o jsonpath='{.metadata.uid}'; }

# The pod's certificate volume is the memory-backed emptyDir the webhook
# adds, which the kubelet keeps under the pod's directory on the node; read
# there, so the first leaf is seen before any workload container runs.
pod_cert_file() {
    if [ -n "${4:-}" ]; then
        pod_cert_file_in "$1" "$2" "$4" "$3"
        return
    fi
    local uid
    uid="$(pod_uid "$1" "$2")" || return
    node_exec cat "/var/lib/kubelet/pods/$uid/volumes/kubernetes.io~empty-dir/c8s-certs/$3" 2>/dev/null || true
}

pod_sandbox_id() {
    local uid
    uid="$(pod_uid "$1" "$2")" || return
    node_exec crictl pods --label "io.kubernetes.pod.uid=$uid" -q | head -1
}

# From the node's store, pulled when absent: the image's entrypoint, then its
# cmd. The kind node image ships jq.
image_entrypoint() {
    image_digest "$1" >/dev/null
    # shellcheck disable=SC2016  # $1 expands on the node
    node_exec sh -c 'crictl inspecti "$1" | jq -r ".info.imageSpec.config | ((.Entrypoint // []) + (.Cmd // []))[]"' _ "$1"
}

# Signed with the harness's operator key, as its own allowlist checks are.
allowlist_put() {
    local code
    code="$(cds_write PUT "/allowlist/workloads/$1" "$2")"
    [ "$code" = 204 ] || { echo "backend: PUT /allowlist/workloads/$1: HTTP $code" >&2; return 1; }
}

allowlist_delete() {
    local code
    code="$(cds_write DELETE "/allowlist/workloads/$1" /dev/null)"
    case "$code" in
        204|404) ;;
        *) echo "backend: DELETE /allowlist/workloads/$1: HTTP $code" >&2; return 1 ;;
    esac
}

# The installer renders the base allowlist into the plugin's config directory
# on the node; a digest is a string that appears nowhere else in it.
base_declares() {
    if node_exec grep -rqF "$2" /etc/nri/conf.d; then echo yes; else echo no; fi
}

# The chart's nriImagePolicy.hostPaths.pluginDir/pluginFilename, which
# containerd launches at its own start (plugin_path), and its runtimeDir/
# healthSocketName, both on the node.
PLUGIN_BIN=/opt/nri/plugins/10-nri-image-policy
PLUGIN_HEALTH=/var/run/nri-image-policy/health.sock

# Refused is exit 7 from curl, as a TLS failure against the CDS is not; the
# kind node image ships curl.
node_refuses() {
    local rc=0
    node_exec curl -sk --max-time 2 -o /dev/null "https://127.0.0.1:$1/healthz" 2>/dev/null || rc=$?
    if [ "$rc" -eq 7 ]; then echo yes; else echo no; fi
}

# The pids running the plugin binary; the kind node image ships procps.
plugin_pids() { node_exec pgrep -f "^$PLUGIN_BIN" || true; }

# The plugin's own /healthz answers 200 once its first pull has settled; the
# kind node image ships curl.
plugin_healthy() {
    node_exec curl -sf --max-time 2 --unix-socket "$PLUGIN_HEALTH" http://localhost/healthz >/dev/null 2>&1
}

# Ready within the installer's budget: a containerd restart, then the first
# pull's bounded retries (2+4+8+16s between attempts) when the CDS is away.
plugin_ready() {
    local deadline=$(($(date +%s) + 300))
    until plugin_healthy; do
        [ "$(date +%s)" -lt "$deadline" ] || { echo "backend: the plugin on $1 is not ready after 300s" >&2; return 1; }
        sleep 2
    done
}

# containerd does not relaunch a plugin that exited, so a killed plugin stays
# down, and required_plugins makes every workload container create fail.
plugin_stop() {
    local pids
    for _ in $(seq 1 30); do
        pids="$(plugin_pids)"
        [ -n "$pids" ] || return 0
        # shellcheck disable=SC2086  # one argument per pid
        node_exec kill $pids 2>/dev/null || true
        sleep 1
    done
    echo "backend: the plugin on $1 is still running" >&2
    return 1
}

# A containerd restart launches the plugins in plugin_path again; shims
# survive it, so running containers do too. The new plugin registers, runs
# its startup check once ready, and pulls afresh (its applied version starts
# over).
plugin_start() {
    node_exec systemctl restart containerd
    for _ in $(seq 1 60); do
        [ -n "$(plugin_pids)" ] && { plugin_ready "$1"; return; }
        sleep 1
    done
    echo "backend: the plugin on $1 did not start" >&2
    return 1
}

# The CDS data volume is an emptyDir here (cds_volatile answers yes): the new
# pod serves the seed at version 1. The port-forward followed the old pod.
cds_restart() {
    kubectl -n "$NS" rollout restart deploy/c8s-cds >/dev/null
    kubectl -n "$NS" rollout status deploy/c8s-cds --timeout=180s >/dev/null
    cds_pf_stop
}

# The number in the weak entity tag W/"<n>" of GET /allowlist.
served_version() { allowlist_get "" | awk 'NR == 1 {print $2}'; }

node_containers() { node_exec crictl ps -a -q --image "$2"; }

dispatch "$@"
