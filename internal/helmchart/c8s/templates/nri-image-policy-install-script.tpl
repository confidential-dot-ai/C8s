{{/*
Install shell script for the NRI plugin. Caller dict: .root, .bootConfig
(rendered image-policy.yaml).
*/}}
{{- define "nri-image-policy.installScript" -}}
{{- $root := .root -}}
set -eu

echo "==> nri-image-policy installer starting"

install_file() {
  src=$1; dst=$2; mode=$3
  mkdir -p "$(dirname "$dst")"
  if cmp -s "$src" "$dst" 2>/dev/null; then
    return 1
  fi
  install -m "$mode" "$src" "$dst.tmp"
  mv -f "$dst.tmp" "$dst"
  return 0
}

write_file() {
  dst=$1; mode=$2
  mkdir -p "$(dirname "$dst")"
  tmp=$(mktemp "$dst.XXXXXX")
  cat > "$tmp"
  chmod "$mode" "$tmp"
  if cmp -s "$tmp" "$dst" 2>/dev/null; then
    rm -f "$tmp"
    return 1
  fi
  mv -f "$tmp" "$dst"
  return 0
}

mkdir -p "/host{{ $root.Values.nriImagePolicy.hostPaths.cacheDir }}"
mkdir -p "/host{{ $root.Values.nriImagePolicy.hostPaths.runtimeDir }}"
# The workload-claims broker socket lives here; the non-root get-cert sidecar
# must traverse the dir (o+x) to connect. Pin it explicitly so a strict root
# umask can't drop o+x (get-cert is fail-closed — no traversal, no cert). Not
# world-writable, so an untrusted pod can't swap the socket.
chmod 0711 "/host{{ $root.Values.nriImagePolicy.hostPaths.runtimeDir }}"

# Written separately from the boot config so it never participates in the
# config-changed comparison that decides whether to restart containerd.
printf '%s' "${NODE_IP:?NODE_IP is required}" > "/host{{ $root.Values.nriImagePolicy.hostPaths.runtimeDir }}/node-ip"
chmod 0644 "/host{{ $root.Values.nriImagePolicy.hostPaths.runtimeDir }}/node-ip"

config_changed=0
if write_file "/host{{ include "nri-image-policy.hostConfigPath" $root }}" 0644 <<'IMAGE_POLICY_EOF'
{{ .bootConfig }}
IMAGE_POLICY_EOF
then
  config_changed=1
  echo "boot config updated"
{{- if $root.Values.nriImagePolicy.policy.exemptNamespaces }}
  # A rewritten boot config is the one event that re-captures the exempt-namespace
  # snapshot: drop the stale file so the plugin freezes a fresh one from what is
  # running now. A plain restart or reboot leaves the config unchanged and keeps
  # the frozen snapshot — the plugin reloads it rather than re-learning.
  rm -f "/host{{ $root.Values.nriImagePolicy.hostPaths.cacheDir }}/exempt-snapshot.json"
{{- end }}
fi

binary_changed=0
if install_file /usr/local/bin/nri-image-policy "/host{{ include "nri-image-policy.hostPluginPath" $root }}" 0755; then
  binary_changed=1
  echo "plugin binary updated"
fi

CONTAINERD_DIR=/host{{ include "nri-image-policy.containerdConfigDir" $root }}
CONTAINERD_CONFIG_MODE={{ include "nri-image-policy.containerdConfigMode" $root | quote }}
MARK_BEGIN='# BEGIN c8s-nri-image-policy (managed)'
MARK_END='# END c8s-nri-image-policy (managed)'

# containerd/RKE2 always render the active config to config.toml.
main_config="$CONTAINERD_DIR/config.toml"

render_nri_toml() {
  cat <<EOF
[plugins."io.containerd.nri.v1.nri"]
  disable = false
  plugin_path = "{{ $root.Values.nriImagePolicy.hostPaths.pluginDir }}"
  plugin_config_path = "{{ $root.Values.nriImagePolicy.hostPaths.configDir }}"
  plugin_registration_timeout = "10s"
  plugin_request_timeout = "2s"
  socket_path = "/var/run/nri/nri.sock"
[plugins."io.containerd.nri.v1.nri.default_validator"]
  enable = true
  required_plugins = ["{{ $root.Values.nriImagePolicy.pluginName }}"]
EOF
}

read_managed_block() {
  awk -v b="$MARK_BEGIN" -v e="$MARK_END" '
    $0==b { in_block=1 }
    in_block { print }
    $0==e { in_block=0 }
  ' "$1" 2>/dev/null || true
}

containerd_changed=0
if [ "$CONTAINERD_CONFIG_MODE" = "dropin" ]; then
  ver=$(sed -n '/^[[:space:]]*\[/q; s/#.*//; s/^[[:space:]]*version[[:space:]]*=[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$main_config" | head -n1)
  if [ "${ver:-0}" -ge 3 ] 2>/dev/null; then
    dropin_dir="$CONTAINERD_DIR/config-v3.toml.d"
  elif [ "${ver:-}" = "2" ]; then
    dropin_dir="$CONTAINERD_DIR/config.toml.d"
  else
    echo "ERROR: cannot determine containerd schema version from $main_config" >&2
    exit 1
  fi
  CONFIG="$dropin_dir/nri-image-policy.toml"
  if ! grep -qF "$(basename "$dropin_dir")" "$main_config" 2>/dev/null; then
    echo "ERROR: $main_config does not import $(basename "$dropin_dir"); containerd-prep should have added it" >&2
    exit 1
  fi
  desired=$(render_nri_toml)
  mkdir -p "$dropin_dir"
  if ! printf '%s\n' "$desired" | cmp -s - "$CONFIG" 2>/dev/null; then
    containerd_changed=1
    printf '%s\n' "$desired" > "$CONFIG.tmp"
    mv -f "$CONFIG.tmp" "$CONFIG"
    echo "containerd drop-in written: $CONFIG"
  fi
else
  CONFIG="$main_config"
  desired=$(printf '%s\n%s\n%s' "$MARK_BEGIN" "$(render_nri_toml)" "$MARK_END")
  if [ "$(read_managed_block "$CONFIG")" != "$desired" ]; then
    containerd_changed=1
    if [ -f "$CONFIG" ]; then
      awk -v b="$MARK_BEGIN" -v e="$MARK_END" '
        $0==b { skip=1; next }
        $0==e { skip=0; next }
        !skip { print }
      ' "$CONFIG" > "$CONFIG.tmp"
    else
      : > "$CONFIG.tmp"
    fi
    printf '\n%s\n' "$desired" >> "$CONFIG.tmp"
    mv -f "$CONFIG.tmp" "$CONFIG"
    echo "containerd config patched: $CONFIG"
  fi
fi

restart_needed=0
if [ "$containerd_changed" = "1" ] || [ "$binary_changed" = "1" ] || [ "$config_changed" = "1" ]; then
  restart_needed=1
fi
{{ include "nri-image-policy.restartAndWait" (dict "root" $root) }}
{{- end }}

{{/*
Restart + readiness tail, shared by the installer and the node-as-CVM pins
script. NRI does not respawn pre-registered plugins on exit, so a binary,
config or containerd-registration change reaches the plugin only through a
containerd restart. Shims survive it.

Caller dict: .root. The script must set restart_needed to 0 or 1 first.
*/}}
{{- define "nri-image-policy.restartAndWait" -}}
{{- $root := .root -}}
RESTART_COMMAND={{ include "nri-image-policy.restartCommand" $root | quote }}
restarted_containerd=0
if [ "$restart_needed" = "1" ]; then
  restarted_containerd=1
  echo "restarting containerd (detached via systemd-run): $RESTART_COMMAND"
  # The restart tears down this pod's own containerd shim. Running it in this
  # pod's process tree (nsenter ... sh -c) means it is killed together with the
  # pod mid-restart — and on a sole control-plane node that interrupts the rke2
  # bootstrap and wedges it (etcd/apiserver static manifests never rewritten,
  # API server stays down). Hand the restart to host PID 1 via systemd-run so it
  # runs as a transient unit and completes regardless of this pod's fate. The
  # RESTART_COMMAND is `systemctl restart ...`, so systemd — and thus
  # systemd-run — is always present on the host.
  # shellcheck disable=SC2086
  nsenter -t 1 -m -u -i -n -p -- \
    systemd-run --collect --description="c8s nri-image-policy containerd restart" \
    sh -c "$RESTART_COMMAND"
fi

# The plugin goes ready once its initial CDS pull settles: 4 backoff sleeps
# (2+4+8+16s) plus per-attempt fetch timeouts (allowlistApi* consts in
# internal/cmds/nri-image-policy/main.go). A containerd restart adds the
# runtime's own recovery, and on a sole control-plane node that takes the
# apiserver down with it, so the budget is wider when we restarted it.
budget=120
if [ "$restarted_containerd" = "1" ]; then
  budget=300
fi
# A wall-clock deadline, so the number in the failure message is the time that
# actually passed: each miss costs the curl timeout as well as the sleep.
deadline=$(($(date +%s) + budget))

health_socket="/host{{ include "nri-image-policy.hostHealthSocket" $root }}"
until health=$(curl --unix-socket "$health_socket" --silent --fail --max-time 2 \
    --write-out ' [http %{http_code}]' http://localhost/healthz 2>&1); do
  if [ "$(date +%s)" -ge "$deadline" ]; then
    # Re-read without --fail so the body and status come back rather than
    # being discarded: the plugin says why it is not ready, and curl exit 7
    # (nothing listening on the socket) is a different fault entirely.
    rc=0
    last=$(curl --unix-socket "$health_socket" --silent --max-time 2 \
      --write-out ' [http %{http_code}]' http://localhost/healthz 2>&1) || rc=$?
    echo "ERROR: plugin not healthy after ${budget}s; last /healthz: ${last:-<no response>} (curl exit $rc)" >&2
    echo "       the plugin runs under containerd, so its log is the journal of the unit restarted by: $RESTART_COMMAND" >&2
    exit 1
  fi
  sleep 1
done
echo "==> nri-image-policy installer finished; plugin healthy: $health"
{{- end }}

{{/*
Pins script for a node-as-CVM (--cvm-mode=bare-metal), where the node image bakes the
plugin binary, its containerd registration and the boot config — base included,
whose RKE2 system digests only the image build resolves. This release's CDS pins
are the one thing that config cannot carry, so the installer patches those two
keys into it and restarts containerd when they change.

Caller dict: .root.
*/}}
{{- define "nri-image-policy.pinsScript" -}}
{{- $root := .root -}}
set -eu

echo "==> nri-image-policy pins installer starting"

result=$(/usr/local/bin/c8s nri-image-policy set-cds-pins \
  --config "/host{{ include "nri-image-policy.hostConfigPath" $root }}" \
  --cds-measurements {{ join "," $root.Values.cds.measurements | quote }} \
  --cds-rtmrs {{ join "," $root.Values.cds.rtmrs | quote }})
echo "CDS pins $result"

restart_needed=0
if [ "$result" = "updated" ]; then
  restart_needed=1
fi
{{ include "nri-image-policy.restartAndWait" (dict "root" $root) }}
{{- end }}

{{/*
Boot config (image-policy.yaml). Caller passes a dict with .root. Every plugin
runs pull mode (polls CDS); allowlist.base is the boot base for CDS and
any-argv bootstrap digests. Argv-pinned images are admitted by the served seed.
*/}}
{{- define "nri-image-policy.bootConfig" -}}
{{- $root := .root -}}
{{/* Must stay the value CDS runs with: the two ends of one mutually-attested connection. */}}
platform: {{ $root.Values.cds.armtlsPlatform | quote }}
plugin:
  health_addr: {{ printf "unix://%s" (include "nri-image-policy.hostHealthSocket" $root) | quote }}
workload_claims:
  socket_dir: {{ $root.Values.nriImagePolicy.hostPaths.runtimeDir | quote }}
  # The plugin is launched by containerd on the host, so its /proc is the
  # host's — a caller PID from SO_PEERCRED resolves directly.
  proc_root: "/proc"
  advertise_host: {{ $root.Values.nriImagePolicy.sandboxDigests.advertiseHost | quote }}
  # An injected credential client dials CDS at this node's own address and this
  # port, and its pod ruleset admits exactly that endpoint.
  cds_node_port: {{ required "cds.service.nodePort is required with nriImagePolicy.enabled=true: an injected credential client dials CDS at its own node's address and that port" $root.Values.cds.service.nodePort }}
allowlist:
  pull:
    url: {{ include "c8s.nriCDSURL" $root | quote }}
    interval: {{ $root.Values.nriImagePolicy.refresh.interval | quote }}
    timeout: "30s"
    # Node-local socket served by the DaemonSet's attest-proxy sidecar.
    attestation_api_url: {{ printf "unix://%s" (include "c8s.attestationApiSocket" $root) | quote }}
    cds_measurements:
{{- range $root.Values.cds.measurements }}
      - {{ . | quote }}
{{- else }}
      []
{{- end }}
    cds_rtmrs:
{{- range $root.Values.cds.rtmrs }}
      - {{ . | quote }}
{{- else }}
      []
{{- end }}
  base:
    {{- /* Also the installer's argv pin: JSON key order is defined, toYaml's is not. */ -}}
    {{- $base := include "c8s.baseWorkloads" $root | fromJson -}}
    {{- dict "schema" "c8s.allowlist/v1" "workloads" $base | toJson | nindent 4 }}
containerd:
  socket: {{ include "nri-image-policy.containerdSocket" $root | quote }}
  namespace: {{ $root.Values.nriImagePolicy.containerd.namespace | quote }}
policy:
  mode: {{ $root.Values.nriImagePolicy.policy.mode | quote }}
  enforce_existing: {{ $root.Values.nriImagePolicy.policy.enforceExisting }}
  deny_missing_annotation: {{ $root.Values.nriImagePolicy.policy.denyMissingAnnotation }}
  {{/* Off on every lane this template serves. The sandbox policy defends a node
       TCB against the cluster admin, which needs a measured base allowlist to exempt;
       the base above is rendered from chart values, so the same admin chooses
       it. cvmMode=node runs the node image's baked config instead, where the
       base is measured — see node-guest-image/c8s/image-policy.yaml.in. */}}
  sandbox: "off"
{{- if $root.Values.nriImagePolicy.policy.exemptNamespaces }}
  exempt_namespaces:
{{- range $root.Values.nriImagePolicy.policy.exemptNamespaces }}
    - {{ . | quote }}
{{- end }}
  exempt_snapshot_path: {{ printf "%s/exempt-snapshot.json" $root.Values.nriImagePolicy.hostPaths.cacheDir | quote }}
{{- end }}
  label_rules:
{{- if $root.Values.nriImagePolicy.policy.labelRules }}
{{- toYaml $root.Values.nriImagePolicy.policy.labelRules | nindent 4 }}
{{- else }}
    []
{{- end }}
logging:
  level: {{ $root.Values.nriImagePolicy.logLevel | quote }}
{{- if not $root.Values.node.baked }}
{{/* The mesh policy of an install: the same shape the node image measures
     (node-guest-image/c8s/image-policy.yaml.in), rendered from chart values
     because nothing here is measured. The enforcer accepts it only on this
     lane, which is for test clusters (decision 5). */}}
{{- if not $root.Values.nriImagePolicy.mesh.resolver }}
{{- fail "nriImagePolicy.mesh.resolver is required with a mesh policy: a member pod resolves names through this address and no other" }}
{{- end }}
{{- if and $root.Values.router.enabled (not $root.Values.nriImagePolicy.mesh.clusterRanges) }}
{{- fail "nriImagePolicy.mesh.clusterRanges is required with the router: its egress exception must exclude this cluster's pod and Service ranges, or its dial to a member would leave the pod in the clear" }}
{{- end }}
mesh:
  exempt_namespaces:
    - {{ $root.Release.Namespace | quote }}
    - "kube-system"
  resolver: {{ $root.Values.nriImagePolicy.mesh.resolver | quote }}
{{- if $root.Values.nriImagePolicy.mesh.clusterRanges }}
{{/* This cluster's pod and Service ranges. The acme role of the router's
     namespace is the one identity whose sockets leave the cluster in the
     clear, and its exception excludes these ranges: a dial to a member rides
     the mesh. */}}
  cluster_ranges:
{{- range $root.Values.nriImagePolicy.mesh.clusterRanges }}
    - {{ . | quote }}
{{- end }}
{{- end }}
  capture:
    outbound: {{ include "c8s.meshOutboundPort" $root }}
    inbound: {{ include "c8s.meshInboundPort" $root }}
    health: {{ include "c8s.meshHealthPort" $root }}
{{- if not (include "c8s.attestationApiSocketPresent" $root) }}
{{/* Where no node-local socket serves the attestation-api, the injected
     credential clients verify CDS evidence over this port on their node's own
     address (c8s.attestationApiURL), so their ruleset admits it. */}}
  credential_attestation_port: {{ $root.Values.attestationApi.port }}
{{- end }}
  roles:
    - name: mesh
      uid: {{ include "c8s.meshUID" $root }}
{{/* The credential role is bound by the plugin, to this node's own address and
     the CDS node port above: only the node knows its address. */}}
{{- end }}
{{- end }}
