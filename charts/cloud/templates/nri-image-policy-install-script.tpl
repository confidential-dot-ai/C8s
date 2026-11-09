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

CONTAINERD_DIR=/host{{ include "nri-image-policy.containerdConfigDir" $root }}
RESTART_COMMAND={{ include "nri-image-policy.restartCommand" $root | quote }}
{{ $root.Files.Get "files/scripts/nri-containerd-config.sh" }}

# containerd renders the active config to config.toml. Its absence means this
# node's containerd is not laid out as upstream's: a file holding only the
# managed block below would drop whatever the host configured elsewhere.
main_config="$CONTAINERD_DIR/config.toml"
# The same file as the host's own containerd names it, for the host commands.
main_config_host_path={{ printf "%s/config.toml" (include "nri-image-policy.containerdConfigDir" $root) | squote }}
[ -f "$main_config" ] || { echo "ERROR: $main_config not found; this node's containerd is not laid out as upstream's" >&2; exit 1; }
new_containerd_config="$main_config$CANDIDATE_SUFFIX"
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

refuse() {
  rm -f "$new_containerd_config"
  echo "ERROR: $*; nothing on this node was changed and containerd was not restarted" >&2
  exit 1
}

render_nri_toml() {
  cat <<EOF
[plugins."io.containerd.nri.v1.nri"]
  disable = false
  plugin_path = "{{ $root.Values.nriImagePolicy.hostPaths.pluginDir }}"
  plugin_config_path = "{{ $root.Values.nriImagePolicy.hostPaths.configDir }}"
  plugin_registration_timeout = "10s"
  plugin_request_timeout = "2s"
  socket_path = "/var/run/nri/nri.sock"
[plugins."io.containerd.nri.v1.nri".default_validator]
  enable = true
  required_plugins = ["{{ include "nri-image-policy.pluginName" $root }}"]
EOF
}

# The top-level version key; containerd reads a config without one as
# version 1, whose plugins have other names.
containerd_config_version() {
  awk '
    /^[ \t]*\[/ { exit }
    /^[ \t]*version[ \t]*=/ { sub(/^[^=]*=[ \t]*/, ""); sub(/[ \t]*(#.*)?$/, ""); print; exit }
  ' "$main_config"
}

# The managed block is the same table in config versions 2 and 3.
check_containerd_config_version() {
  version=$(containerd_config_version)
  case "$version" in
    2|3) ;;
    *) refuse "$main_config declares containerd config version ${version:-1}; this installer edits versions 2 and 3" ;;
  esac
}

# Prints $1 with every line of its NRI tables behind HOST_TABLE_MARK. TOML
# quotes a table's key in three ways, so the match is on the bare key.
disable_nri_tables() {
  awk -v mark="$HOST_TABLE_MARK" -v nri="plugins.io.containerd.nri.v1.nri" '
    /^[ \t]*\[/ {
      key = $0
      sub(/^[ \t]*\[/, "", key)
      sub(/\].*$/, "", key)
      gsub(/["'"'"']/, "", key)
      in_nri_table = key == nri || index(key, nri ".") == 1
    }
    in_nri_table { print mark $0; next }
    { print }
  ' "$1"
}

# The host's config with its NRI tables disabled, then the managed block: TOML
# allows a table once, and a second run renders the same bytes.
render_containerd_config() {
  host_containerd_config "$main_config" > "$scratch/host-config.toml"
  disable_nri_tables "$scratch/host-config.toml"
  echo "$MARK_BEGIN"
  render_nri_toml
  echo "$MARK_END"
}

# Lines of $1 that set NRI outside a table of its own (dotted keys, inline
# tables), which disabling the NRI tables leaves in force.
nri_settings_outside_a_table() {
  awk -v b="$MARK_BEGIN" -v e="$MARK_END" '
    $0 == b { in_block = 1; next }
    $0 == e { in_block = 0; next }
    !in_block && /^[ \t]*[^# \t]/ && index($0, "io.containerd.nri.v1.nri") { print }
  ' "$1"
}

# The paths the boot config names its inputs by, which the plugin opens at
# start.
boot_cds_address={{ include "nri-image-policy.hostCDSAddressPath" $root | squote }}
boot_cds_pin={{ include "nri-image-policy.hostCDSPinPath" $root | squote }}
boot_syslog={{ include "nri-image-policy.syslogSocket" $root | squote }}

# Stages what the boot config names in this pod's root, at the paths it names
# them: the CDS address and pin, and the host's syslog socket.
stage_boot_config_inputs() {
  install -D -m 0644 {{ include "nri-image-policy.cdsPolicyMount" $root }}/cds-address "$boot_cds_address"
  install -D -m 0644 {{ include "nri-image-policy.cdsPolicyMount" $root }}/cds.json "$boot_cds_pin"
  host_syslog=$(nsenter -t 1 -m -- readlink -e {{ include "nri-image-policy.syslogSocket" $root | squote }}) ||
    refuse "the host has no syslog socket at {{ include "nri-image-policy.syslogSocket" $root }}, which the plugin logs to"
  ln -sfn "/proc/1/root$host_syslog" "$boot_syslog"
}

check_boot_config() {
  /usr/local/bin/nri-image-policy check-config --config="$1" ||
    refuse "the plugin refuses the boot config it would start with"
}

# Leaves the containerd config this node needs beside the current one when the
# two differ, and sets containerd_config_staged to 1 when it did.
stage_containerd_config() {
  containerd_config_staged=0
  at_most_one_managed_block "$main_config" ||
    refuse "$main_config holds the c8s-nri-image-policy BEGIN/END markers unpaired or twice; leave one managed block or none"
  check_containerd_config_version
  render_containerd_config > "$new_containerd_config"
  if cmp -s "$new_containerd_config" "$main_config"; then
    rm -f "$new_containerd_config"
    return
  fi
  foreign=$(nri_settings_outside_a_table "$new_containerd_config")
  [ -z "$foreign" ] || refuse "$main_config configures NRI outside a table of its own: $foreign"
  containerd_config_staged=1
}

# The config containerd runs with once it loads $1, named $2 on the host and
# its imports merged, must require the plugin before any container starts. Its
# dump can hold registry credentials, so no message quotes it.
check_effective_containerd_config() {
  dump=$(nsenter -t 1 -m -- containerd --config "$2" config dump 2> "$scratch/dump-errors") ||
    refuse "the host's containerd cannot load $1: $(cat "$scratch/dump-errors")"
  printf '%s\n' "$dump" | /usr/local/bin/nri-image-policy check-containerd-config \
    --plugin-dir={{ $root.Values.nriImagePolicy.hostPaths.pluginDir | squote }} \
    --required-plugin={{ include "nri-image-policy.pluginName" $root | squote }} ||
    refuse "the host's containerd would start containers without the plugin under $1"
}

boot_config="$scratch/image-policy.yaml"
cat > "$boot_config" <<'IMAGE_POLICY_EOF'
{{ .bootConfig }}
IMAGE_POLICY_EOF
stage_boot_config_inputs
check_boot_config "$boot_config"
stage_containerd_config
if [ "$containerd_config_staged" = "1" ]; then
  check_effective_containerd_config "$new_containerd_config" "$main_config_host_path$CANDIDATE_SUFFIX"
else
  check_effective_containerd_config "$main_config" "$main_config_host_path"
fi

mkdir -p "/host{{ include "nri-image-policy.runtimeDir" $root }}"
# The workload-claims broker socket lives here; the non-root get-cert sidecar
# must traverse the dir (o+x) to connect. Pin it explicitly so a strict root
# umask can't drop o+x (get-cert is fail-closed — no traversal, no cert). Not
# world-writable, so an untrusted pod can't swap the socket.
chmod 0711 "/host{{ include "nri-image-policy.runtimeDir" $root }}"

# The CDS this cluster trusts, beside the boot config. The NRI required_plugins
# this script writes hold from the moment it has run on this boot.
cds_changed=0
if install_file \
  {{ include "nri-image-policy.cdsPolicyMount" $root }}/cds-address \
  "/host{{ include "nri-image-policy.hostCDSAddressPath" $root }}" \
  0644; then
  cds_changed=1
  echo "CDS address updated"
fi
if install_file \
  {{ include "nri-image-policy.cdsPolicyMount" $root }}/cds.json \
  "/host{{ include "nri-image-policy.hostCDSPinPath" $root }}" \
  0644; then
  cds_changed=1
  echo "CDS pin updated"
fi

config_changed=0
if write_file "/host{{ include "nri-image-policy.hostConfigPath" $root }}" 0644 < "$boot_config"
then
  config_changed=1
  echo "boot config updated"
fi

binary_changed=0
if install_file /usr/local/bin/nri-image-policy "/host{{ include "nri-image-policy.hostPluginPath" $root }}" 0755; then
  binary_changed=1
  echo "plugin binary updated"
fi

if [ "$containerd_config_staged" = "1" ]; then
  replace_durably "$new_containerd_config" "$main_config"
  echo "containerd config patched: $main_config"
fi

restart_needed=0
if [ "$containerd_config_staged" = "1" ] ||
  [ "$binary_changed" = "1" ] ||
  [ "$config_changed" = "1" ] ||
  [ "$cds_changed" = "1" ]; then
  restart_needed=1
fi
{{ include "nri-image-policy.restartAndWait" (dict "root" $root) }}
{{- end }}

{{/*
The installer's restart and readiness tail. NRI does not respawn pre-registered plugins on exit, so a binary,
config or containerd-registration change reaches the plugin only through a
containerd restart. Shims survive it.

Caller dict: .root. The script must include nri-containerd-config.sh, set
RESTART_COMMAND, and set restart_needed to 0 or 1 first.
*/}}
{{- define "nri-image-policy.restartAndWait" -}}
{{- $root := .root -}}

# A plugin that already died stays dead until containerd restarts, and this
# pod's plugin-ready container would then hold the rollout forever. Restart
# for that too, at most once per window: a plugin that dies again right away
# gets the health failure below, not a containerd restart per init retry. The
# stamp is on tmpfs, so a reboot clears it.
#
# A plugin whose health socket still answers is alive whatever the process
# check says, so a check that misreads this node's process tree leaves the
# pod NotReady rather than restarting the runtime.
if [ "$restart_needed" = "0" ] && ! /usr/local/bin/c8s nri-image-policy plugin-ready --check \
    --plugin-path={{ include "nri-image-policy.hostPluginPath" $root | squote }}; then
  if curl --unix-socket "/host{{ include "nri-image-policy.hostHealthSocket" $root }}" --silent --fail \
      --max-time 2 --output /dev/null http://localhost/healthz; then
    echo "WARNING: plugin health socket answers but no plugin process was found under containerd; not restarting" >&2
  else
    stamp="/host{{ include "nri-image-policy.runtimeDir" $root }}/dead-plugin-restart"
    now=$(date +%s)
    last=$(cat "$stamp" 2>/dev/null || true)
    case "$last" in ''|*[!0-9]*) last=0 ;; esac
    if [ $((now - last)) -ge 600 ]; then
      echo "plugin not running; restarting containerd to relaunch it"
      printf '%s\n' "$now" > "$stamp"
      restart_needed=1
    else
      echo "plugin not running; containerd was restarted for that $((now - last))s ago, not again within 600s" >&2
    fi
  fi
fi

restarted_containerd=0
if [ "$restart_needed" = "1" ]; then
  restarted_containerd=1
  restart_containerd
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
    echo "       the plugin's journal (journalctl -t nri-image-policy) ends:" >&2
    nsenter -t 1 -m -- journalctl -t nri-image-policy -n 50 --no-pager >&2 || true
    exit 1
  fi
  sleep 1
done
echo "==> nri-image-policy installer finished; plugin healthy: $health"
{{- end }}

{{/*
Boot config (image-policy.yaml). Caller passes a dict with .root. Every plugin
runs pull mode (polls CDS); allowlist.base is the boot base for CDS and
any-argv bootstrap digests. Argv-pinned images are admitted by the served seed.
*/}}
{{- define "nri-image-policy.bootConfig" -}}
{{- $root := .root -}}
{{/* Must stay the value CDS runs with: the two ends of one mutually-attested connection. */}}
platform: {{ $root.Values.nriImagePolicy.platform | quote }}
plugin:
  health_addr: {{ printf "unix://%s" (include "nri-image-policy.hostHealthSocket" $root) | quote }}
workload_claims:
  socket_dir: {{ include "nri-image-policy.runtimeDir" $root | quote }}
  # The plugin is launched by containerd on the host, so its /proc is the
  # host's — a caller PID from SO_PEERCRED resolves directly.
  proc_root: "/proc"
  advertise_host: ""
  # Components read node-ip as their attestation-api host, so the plugin
  # writes it from the host's view; this pod's environment is not pinned.
  publish_node_ip: true
allowlist:
  pull:
    interval: "5s"
    timeout: "30s"
    # Node-local socket served by the DaemonSet's attest-proxy sidecar.
    attestation_api_url: {{ printf "unix://%s" (include "c8s.attestationApiSocket" $root) | quote }}
    # The CDS this cluster trusts, installed beside this config from the
    # ConfigMap the installer mounts: the endpoint the plugin pulls from and
    # hands its injected credential clients, and the pin they hold it to.
    # Paths, so no argument of a component names the CDS it is served by.
    cds_address_file: {{ include "nri-image-policy.hostCDSAddressPath" $root | quote }}
    cds_measurements_config: {{ include "nri-image-policy.hostCDSPinPath" $root | quote }}
  base:
    {{- /* Also the installer's argv pin: JSON key order is defined, toYaml's is not. */ -}}
    {{- $base := include "c8s.baseWorkloads" (dict "root" $root "templates" (include "c8s.componentPodTemplates" $root)) | fromJson -}}
    {{- dict "schema" "c8s.allowlist/v1" "workloads" $base | toJson | nindent 4 }}
containerd:
  socket: {{ include "nri-image-policy.containerdSocket" $root | quote }}
  namespace: "k8s.io"
policy:
  mode: {{ $root.Values.nriImagePolicy.policy.mode | quote }}
  enforce_existing: true
  deny_missing_annotation: true
  {{/* Off on every lane this template serves. The sandbox policy defends a node
       TCB against the cluster admin, which needs a measured base allowlist to exempt;
       the base above is rendered from chart values, so the same admin chooses
       it. A worker image runs its measured config instead, whose base is
       measured — see images/node-guest/worker/image-policy.yaml.in. */}}
  sandbox: "off"
{{- if $root.Values.nriImagePolicy.policy.exemptNamespaces }}
  exempt_namespaces:
{{- range $root.Values.nriImagePolicy.policy.exemptNamespaces }}
    - {{ . | quote }}
{{- end }}
{{- with $root.Values.nriImagePolicy.policy.exemptDigests }}
  exempt_digests:
{{- range $namespace, $digests := . }}
    {{ $namespace | quote }}:
{{- range $digests }}
      - {{ . | quote }}
{{- end }}
{{- end }}
{{- end }}
{{- end }}
  label_rules:
    []
logging:
  level: "info"
  syslog: {{ include "nri-image-policy.syslogSocket" $root | quote }}
{{/* The mesh policy of an install: the same shape the node image measures
     (images/node-guest/worker/image-policy.yaml.in), rendered from chart values
     because nothing here is measured. The enforcer accepts it only on this
     lane, which is for test clusters (decision 5). */}}
{{- if not $root.Values.nriImagePolicy.mesh.resolver }}
{{- fail "nriImagePolicy.mesh.resolver is required with a mesh policy: a member pod resolves names through this address and no other" }}
{{- end }}
{{- if not $root.Values.nriImagePolicy.mesh.clusterRanges }}
{{- fail "nriImagePolicy.mesh.clusterRanges is required with the router: its egress exception must exclude this cluster's pod and Service ranges, or its dial to a member would leave the pod in the clear" }}
{{- end }}
mesh:
  exempt_namespaces:
{{- include "nri-image-policy.meshExemptNamespaces" $root | nindent 4 }}
  resolver: {{ $root.Values.nriImagePolicy.mesh.resolver | quote }}
{{/* This cluster's pod and Service ranges. The acme role of the router's
     namespace is the one identity whose sockets leave the cluster in the
     clear, and its exception excludes these ranges: a dial to a member rides
     the mesh. */}}
  cluster_ranges:
{{- range $root.Values.nriImagePolicy.mesh.clusterRanges }}
    - {{ . | quote }}
{{- end }}
  capture:
    outbound: {{ include "c8s.meshOutboundPort" $root }}
    inbound: {{ include "c8s.meshInboundPort" $root }}
    health: {{ include "c8s.meshHealthPort" $root }}
  roles:
    - name: mesh
      uid: {{ include "c8s.meshUID" $root }}
{{/* The credential role is bound by the plugin, to this node's own address and
     the CDS node port above: only the node knows its address. */}}
{{- end }}
