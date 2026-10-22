#!/usr/bin/env bash
# metal-dev backend: a metal lane's C8S_DEV=1 SSH node image, the same single
# node and real TEE as metal.sh, built without the pod exec policy and with
# root SSH by the launch key. The lane's dev-node-shell.sh gives the suite a
# node shell and the node's RKE2 admin kubeconfig, so what metal.sh answers
# 77 for want of exec, a node shell or writes in the c8s namespace runs here
# as on kind. It is a different measurement from the shipped image.
# Interface: common.sh.

: "${C8S_NODE_SSH_CONFIG:?the ssh config dev-node-shell.sh wrote (host "node")}"
: "${C8S_ADMIN_KUBECONFIG:?the node admin kubeconfig dev-node-shell.sh wrote}"
export KUBECONFIG="$C8S_ADMIN_KUBECONFIG"
# shellcheck source=metal.sh
. "$(dirname "${BASH_SOURCE[0]}")/metal.sh"
# metal.sh answers 77 where the locked image closes exec and has no shell;
# here the shared implementations hold again.
# shellcheck source=common.sh
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
PLATFORM="${SUITE_PLATFORM:-metal-dev} (C8S_DEV=1 image)"

RKE2_BIN=/var/lib/rancher/rke2/bin
CONTAINERD_SOCKET=/run/k3s/containerd/containerd.sock
SEED=/run/c8s-node/allowlist-seed.json

# The CDS Service's node port on the guest: the lane's runner reaches every
# port of the guest at the address of the router's front door. Signed writes
# and raw reads go there, as kind's go through its port-forward.
guest_host() { local host="${C8S_ALLOWLIST_URL#https://}"; echo "${host%%[:/]*}"; }
cds_url() {
    local port
    port="$(cached cds-node-port kubectl -n "$NS" get svc c8s-cds -o jsonpath='{.spec.ports[0].nodePort}')" || return
    [ -n "$port" ] || { echo "backend: the CDS Service has no node port" >&2; return 1; }
    echo "https://$(guest_host):$port"
}
# The same listener dialled without TLS; it is TLS-only.
cds_plain_url() { local url; url="$(cds_url)" || return; echo "${url/https:/http:}"; }

# Root on the node, with RKE2's ctr and crictl pointed at its containerd.
node_exec() {
    ssh -n -F "$C8S_NODE_SSH_CONFIG" node "$(printf '%q ' env \
        "PATH=$RKE2_BIN:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
        "CONTAINERD_ADDRESS=$CONTAINERD_SOCKET" "CONTAINER_RUNTIME_ENDPOINT=unix://$CONTAINERD_SOCKET" "$@")"
}

# node_write <path>: stdin to the file on the node.
node_write() { ssh -F "$C8S_NODE_SSH_CONFIG" node "cat > $(printf '%q' "$1")"; }

# The files the router mounts from the image.
router_nginx_conf() { node_exec sh -c 'cat /usr/lib/c8s/router-nginx/*.conf'; }

# Boot staging writes the seed the CDS loads to the node's /run/c8s-node, which
# the CDS mounts and, on a baked node, follows (--follow-seed).
seed_declares() {
    if node_exec grep -qF "$1" "$SEED"; then echo yes; else echo no; fi
}

seed_add() {
    local original
    original="$(scratch)/seed-original.json"
    [ -s "$original" ] || node_exec cat "$SEED" > "$original" || return
    node_exec cat "$SEED" | jq --arg name "$1" --slurpfile entry "$2" '.workloads[$name] = $entry[0]' | node_write "$SEED"
}

seed_restore() {
    local original
    original="$(scratch)/seed-original.json"
    [ -s "$original" ] || return 0
    node_write "$SEED" < "$original" && rm -f "$original"
}

# The outgoing CDS's log is kept first: its pod goes with the restart.
# A CDS without persistence refuses operator tokens issued before its start
# plus --jwt-clock-skew (internal/cmds/cds/tokens.go), whoever mints them,
# the steps included; the restart returns once that has passed.
cds_restart() {
    local skew
    cds_log_keep
    kubectl -n "$NS" rollout restart deploy/c8s-cds >/dev/null
    kubectl -n "$NS" rollout status deploy/c8s-cds --timeout=180s >/dev/null || return
    skew="$(kubectl -n "$NS" get deploy c8s-cds -o json |
        jq -r '[.spec.template.spec.containers[] | select(.name == "cds") | .args[] | select(startswith("--jwt-clock-skew=")) | ltrimstr("--jwt-clock-skew=")] | first')"
    sleep "$((skew + 1))"
}

# The CDS's log, appended to cds.log in the results, so a failed run shows
# what each CDS of the run saw.
cds_log_keep() {
    kubectl -n "$NS" logs deploy/c8s-cds -c cds --timestamps >> "$(scratch)/cds.log" 2>&1 || true
}

# The scenarios' entries go, as on metal, after the last CDS's log is kept.
eval "metal_$(declare -f teardown_backend)"
teardown_backend() {
    cds_log_keep
    metal_teardown_backend
}

# The plugin pulls from the address boot staging wrote into its config (the
# launch's server address at the CDS node port), not 127.0.0.1: RKE2 runs
# kube-proxy without localhost node ports, so loopback refuses whatever the
# Service says. Refused is exit 7 from curl, as a TLS failure is not.
node_refuses() {
    local host rc=0
    host="$(cached plugin-pull-host node_exec sed -nE 's#^ +url: "?https://([^:/"]+).*#\1#p' /etc/nri/conf.d/image-policy.yaml)" || return
    [ -n "$host" ] || { echo "backend: no pull URL in the plugin's config" >&2; return 1; }
    node_exec curl -sk --max-time 2 -o /dev/null "https://$host:$1/healthz" 2>/dev/null || rc=$?
    if [ "$rc" -eq 7 ]; then echo yes; else echo no; fi
}

# RKE2 runs containerd as its child and exits when it does; systemd starts
# RKE2 again, whose containerd launches the plugins in plugin_path. Shims
# survive, so running containers do too.
plugin_start() {
    local deadline=$(($(date +%s) + 300))
    node_exec pkill -x containerd || true
    until [ -n "$(plugin_pids)" ]; do
        [ "$(date +%s)" -lt "$deadline" ] || { echo "backend: the plugin on $1 did not start" >&2; return 1; }
        sleep 2
    done
    plugin_ready "$1"
}

# The node's attestation service is a systemd unit that RKE2, cred-release
# and attest-proxy require, so a stop would take them with it: it is frozen
# instead, and answers nothing until thawed.
attestation_service_stop() { node_exec systemctl freeze attestation-api.service; }
attestation_service_start() { node_exec systemctl thaw attestation-api.service; }

# As on kind, in RKE2's containerd state directory, plus RKE2's own.
private_keys() {
    kubectl get secrets,configmaps -A -o json |
        jq -r '.items[] | (.data // {})[] as $v | if .kind == "Secret" then ($v | @base64d) else $v end'
    # shellcheck disable=SC2016  # expands on the node
    node_exec sh -c '
        cds="$(crictl ps -q --name "^cds$" | head -1)"
        [ -n "$cds" ] || { echo "backend: no cds container on the node" >&2; exit 1; }
        grep -rla -e "PRIVATE KEY-----" "$@" "/run/k3s/containerd/io.containerd.runtime.v2.task/k8s.io/$cds/rootfs" 2>/dev/null | xargs -r cat' _ \
        /etc /run /root /opt /tmp /var/lib/kubelet /var/lib/rancher
}

dispatch "$@"
