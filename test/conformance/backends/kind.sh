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

served_allowlist() {
    cds_pf_start
    curl -sSfk "https://127.0.0.1:$CDS_LOCAL_PORT/allowlist"
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
served_version() {
    cds_pf_start
    curl -sSfk -o /dev/null -D - "https://127.0.0.1:$CDS_LOCAL_PORT/allowlist" |
        awk 'tolower($1) == "etag:" {gsub(/[^0-9]/, "", $2); print $2}'
}

node_containers() { node_exec crictl ps -a -q --image "$2"; }

dispatch "$@"
