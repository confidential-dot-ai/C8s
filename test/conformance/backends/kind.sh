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

teardown_backend() {
    allowlist_delete "$nginx_entry" || true
}

scratch_encrypted() { echo no; }

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

# The router's hostPort 443 on the kind node, reachable on the kind network.
router_url() {
    local ip
    ip="$(kubectl get node "$NODE" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}' | awk '{print $1}')"
    [ -n "$ip" ] || { echo "backend: node $NODE has no InternalIP" >&2; return 1; }
    echo "https://$ip:443"
}
# The CDS outside the cluster is lib.sh's (cds_url), and so are the harness's
# operator key and token minter.
operator_key() { echo "$WORKDIR/operator.key"; }
optoken_bin() { echo "$WORKDIR/optoken"; }
scratch() { echo "$WORKDIR"; }

# The same address dialled without TLS; the listener is TLS-only.
cds_plain_url() { local url; url="$(cds_url)" || return; echo "${url/https:/http:}"; }
cds_pins() { echo "$MOCK_MEASUREMENT"; }
# Every client of this cluster dials the one CDS, pods included.
cds_pod_url() { cds_url; }

# The flags the harness runs the CDS with (lib.sh, cds_serve); empty for one it
# leaves at the CDS's own default.
cds_arg() {
    docker inspect -f '{{json .Args}}' "$CDS_CONTAINER" |
        jq -r --arg p "--$1=" '.[] | select(startswith($p)) | ltrimstr($p)' | tail -1
}

# The CDS runs from the configuration its launch binds it to, so only a
# parameter outside that file can be changed here: the harness replaces the
# container with one that carries it (lib.sh, cds_serve), and default brings
# the installed command line back. Node pins, the operator key and the
# inventory range are the configuration's, which a restart cannot change
# without breaking the binding every client checks.
cds_restart_with() {
    case "$1" in
        default) cds_serve ;;
        san-validation) cds_serve "--san-validation=$2" ;;
        pins | operator-keys | inventory-cidr) return "$UNSUPPORTED" ;;
        *) echo "backend: cds_restart_with: no parameter '$1'" >&2; return 2 ;;
    esac
    cds_wait
}

# The CDS reads its attestation-api over loopback in CDS_ATTESTATION_CONTAINER's
# network namespace (lib.sh, cds_serve: --network container, --attestation-api-url
# http://127.0.0.1:8400); the cluster's kube-system mock serves the node-baked
# api that the node's mesh members and the host plugin use, not the CDS. So the
# scenario that takes the CDS's own attestation away pauses that container: the
# process stops answering while the namespace and the CDS's network stay up, so
# the CDS stays reachable and its background readiness probe (bounded per
# interval) flips /readyz to 503. docker rm/stop would instead drop the shared
# namespace and the CDS with it.
attestation_service_stop() {
    docker pause "$CDS_ATTESTATION_CONTAINER" >/dev/null
}

# Unpause, then wait for the CDS to report ready again before returning, so the
# next scenario does not inherit a 503. /readyz, not /healthz: readiness is what
# the probe drives and what the scenario read.
attestation_service_start() {
    docker unpause "$CDS_ATTESTATION_CONTAINER" >/dev/null
    local deadline=$(($(date +%s) + 60))
    until [ "$(curl -sk -o /dev/null -w '%{http_code}' "$(cds_url)/readyz")" = 200 ]; do
        [ "$(date +%s)" -lt "$deadline" ] || { echo "backend: the CDS did not report ready 60s after its attestation returned" >&2; return 1; }
        sleep 1
    done
}

# PEM private keys outside CDS process memory: in the Secrets and ConfigMaps
# of every namespace, and in the files of the node. The files are emitted
# as they are, binary ones included, and the reader picks the PEM blocks
# out of them. "Every file on the node" is the directories where
# configuration and state live, which a scan of the whole overlay would only
# add time to; /proc, /sys and /dev are not files. The CDS runs outside the
# cluster, so its own filesystem is as out of reach here as a CDS VM's.
private_keys() {
    kubectl get secrets,configmaps -A -o json |
        jq -r '.items[] | (.data // {})[] as $v | if .kind == "Secret" then ($v | @base64d) else $v end'
    # shellcheck disable=SC2016  # expands on the node
    node_exec sh -c 'grep -rla -e "PRIVATE KEY-----" "$@" 2>/dev/null | xargs -r cat' _ \
        /etc /run /root /opt /tmp /var/lib/kubelet
}

# One issuance from this host, with the CLI the harness built: the mock
# admits it like any requester, the CDS is pinned by the document the cluster
# trusts it under, and the CSR carries a DNS SAN the CDS's Service pattern
# admits and no IP SAN (the source address the CDS sees is this host's).
attest_direct() {
    local bin="$C8S_ROOT/build/c8s"
    [ -x "$bin" ] || make -C "$C8S_ROOT" build-c8s >&2 || return 1
    "$bin" get-cert --cds-url "$(cds_url)" --attestation-api-url "$(mock_attestation_url)" \
        --image-policy-file "$WORKDIR/cds/cds-pin.json" --san "requester.$NS.svc" 2>/dev/null
}

# The mock issues a version-2 SNP report over any report data, with an
# all-zero launch measurement (the pin the CDS was installed with), and
# reports every signature valid; its verifier reads the launch digest from
# the report it is shown. Its evidence verifies nowhere but at the mock, so no
# verifier on this host can act as a relying party.
evidence() {
    jq -n --arg rd "$3" '{report_data: $rd}' |
        curl -sf --max-time 20 -H 'Content-Type: application/json' --data-binary @- "$(mock_attestation_url)/attest"
}
evidence_signed() { echo no; }
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
    node_exec crictl pods --label "io.kubernetes.pod.uid=$uid" -q | awk 'NR == 1'
}

# From the node's store, pulled when absent: the image's entrypoint, then its
# cmd. The kind node image ships jq.
image_entrypoint() {
    image_digest "$1" >/dev/null
    # shellcheck disable=SC2016  # $1 expands on the node
    node_exec sh -c 'crictl inspecti "$1" | jq -r ".info.imageSpec.config | ((.Entrypoint // []) + (.Cmd // []))[]"' _ "$1"
}

image_env() {
    image_digest "$1" >/dev/null
    # shellcheck disable=SC2016  # $1 expands on the node
    node_exec sh -c 'crictl inspecti "$1" | jq -r ".info.imageSpec.config | (.Env // [])[]"' _ "$1"
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
PLUGIN_HEALTH=/run/nri-image-policy/health.sock

# The plugin pulls from the CDS the install mounted on the node, out of the
# node's own network namespace; every pod's get-cert dials that same address
# from its own. A reject rule on the connections the node itself opens
# refuses each pull at once and leaves issuance, and so every pod's start,
# alone: a pod's packets are forwarded, never the node's own output.
cds_block_rule() {
    echo OUTPUT -p tcp -d "$(cds_host)" --dport "$CDS_PORT" \
        -m comment --comment c8s-conformance-cds-block -j REJECT --reject-with tcp-reset
}
cds_block() {
    local rule
    rule="$(cds_block_rule)" || return
    # shellcheck disable=SC2086  # the rule's words
    node_exec iptables -C $rule 2>/dev/null || node_exec iptables -I $rule || return
    local deadline=$(($(date +%s) + 60))
    until [ "$(node_refuses)" = yes ]; do
        [ "$(date +%s)" -lt "$deadline" ] || { echo "backend: the node still accepts pulls on $CDS_PORT after 60s" >&2; return 1; }
        sleep 1
    done
}
cds_unblock() {
    local rule
    rule="$(cds_block_rule)" || return
    # shellcheck disable=SC2086  # the rule's words
    while node_exec iptables -C $rule 2>/dev/null; do node_exec iptables -D $rule || return; done
}

# A connect that fails or hangs is refused: a reset may never reach the
# socket, so the dial times out instead.
node_refuses() {
    if node_exec timeout 2 bash -c "</dev/tcp/$(cds_host)/$CDS_PORT" 2>/dev/null; then echo no; else echo yes; fi
}

# The same reject, on the router pod's packets alone: they are forwarded by
# the node, so the relay loses the CDS while the plugin's pulls and every
# other pod's issuance keep it. A rule left behind for a router pod that has
# since been replaced names an address nothing holds.
cds_relay_rule() {
    local selector pod
    selector="$(kubectl -n "$ROUTER_NS" get deploy "$ROUTER_DEPLOY" -o json |
        jq -r '.spec.selector.matchLabels | to_entries | map("\(.key)=\(.value)") | join(",")')" || return
    pod="$(kubectl -n "$ROUTER_NS" get pods -l "$selector" -o jsonpath='{.items[*].status.podIP}')" || return
    [ "$(wc -w <<<"$pod")" = 1 ] || { echo "backend: want one router pod address in $ROUTER_NS, got '$pod'" >&2; return 1; }
    echo FORWARD -p tcp -s "$pod" -d "$(cds_host)" --dport "$CDS_PORT" \
        -m comment --comment c8s-conformance-relay-block -j REJECT --reject-with tcp-reset
}
cds_relay_block() {
    local rule
    rule="$(cds_relay_rule)" || return
    # shellcheck disable=SC2086  # the rule's words
    node_exec iptables -C $rule 2>/dev/null || node_exec iptables -I $rule
}
cds_relay_unblock() {
    local rule
    rule="$(cds_relay_rule)" || return
    # shellcheck disable=SC2086  # the rule's words
    while node_exec iptables -C $rule 2>/dev/null; do node_exec iptables -D $rule || return; done
}

# The pids running the plugin binary; the kind node image ships procps.
plugin_pids() { node_exec pgrep -f "^$PLUGIN_BIN" || true; }

# The plugin's own /healthz answers 200 once its first pull has settled; the
# kind node image ships curl.
plugin_healthy() {
    node_exec curl -sf --max-time 2 --unix-socket "$PLUGIN_HEALTH" http://localhost/healthz >/dev/null 2>&1
}

# The version in that answer, whatever its status: the one the plugin applied.
applied_version() {
    node_exec curl -s --max-time 2 --unix-socket "$PLUGIN_HEALTH" http://localhost/healthz | jq -r .allowlist_version
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

# The store does not outlive the container (cds_volatile answers yes): the new
# one serves the configuration's entries at version 1.
cds_restart() {
    cds_serve
    cds_wait
}

# The number in the weak entity tag W/"<n>" of GET /allowlist.
node_containers() { node_exec crictl ps -a -q --image "$2"; }

dispatch "$@"
