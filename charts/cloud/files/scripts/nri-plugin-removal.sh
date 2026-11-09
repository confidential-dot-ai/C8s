# shellcheck shell=sh
# NRI image-policy plugin removal, run by the C8s host sweep after
# nri-containerd-config.sh. Every function returns non-zero on failure and
# leaves what a retry needs.
: "${MARK_BEGIN:?set by nri-containerd-config.sh, which the caller includes first}"
CONTAINERD_DIR="/host${HOST_CONTAINERD_DIR:?the containerd config directory of this node}"
RESTART_COMMAND="${RESTART_COMMAND:?the containerd restart command of this node}"

# Seconds the plugin has to exit after a containerd restart.
PLUGIN_EXIT_BUDGET_SECONDS=60

# restore_host_containerd_config's answer, which decides the restart.
CONFIG_RESTORED=2

# Succeeds while containerd runs a plugin on this node. The pods that call this
# share the host PID namespace, so the pod's own /proc is the node's. An answer
# the scan cannot give counts as a running plugin.
plugin_running() {
  running=0
  /usr/local/bin/c8s nri-image-policy plugin-running --proc-root=/proc || running=$?
  if [ "$running" = 1 ]; then
    return 1
  fi
  if [ "$running" != 0 ]; then
    echo "warning: counting the plugin as running: the scan could not answer" >&2
  fi
  return 0
}

# Restores the host's containerd config and drops the installer's staged one.
# Returns $CONFIG_RESTORED when config.toml changed, 0 when it was the host's
# already.
restore_host_containerd_config() {
  config="$CONTAINERD_DIR/config.toml"
  rm -f "$config$CANDIDATE_SUFFIX" || return 1
  [ -f "$config" ] || return 0
  if ! at_most_one_managed_block "$config"; then
    echo "ERROR: $config holds the c8s-nri-image-policy BEGIN/END markers unpaired or twice; leave one managed block or none, then re-run" >&2
    return 1
  fi
  host_containerd_config "$config" > "$config.tmp" || return 1
  if cmp -s "$config.tmp" "$config"; then
    rm -f "$config.tmp"
    return 0
  fi
  replace_durably "$config.tmp" "$config" || return 1
  echo "containerd config restored: $config"
  return "$CONFIG_RESTORED"
}

wait_for_plugin_exit() {
  waited=0
  while plugin_running; do
    if [ "$waited" -ge "$PLUGIN_EXIT_BUDGET_SECONDS" ]; then
      echo "ERROR: the nri-image-policy plugin still runs after the containerd restart (waited ${waited}s)" >&2
      return 1
    fi
    sleep 1
    waited=$((waited + 1))
  done
}

# Deletes the plugin binaries "$@" that are on this node.
remove_plugin_binaries() {
  for binary in "$@"; do
    [ -e "$binary" ] || continue
    rm -f "$binary" || return 1
  done
}

# Takes the plugin out of containerd: the host's config back, the binaries "$@"
# deleted before the restart so containerd launches none, and no plugin left
# running.
remove_plugin_from_containerd() {
  restored=0
  restore_host_containerd_config || restored=$?
  [ "$restored" = 0 ] || [ "$restored" = "$CONFIG_RESTORED" ] || return 1
  remove_plugin_binaries "$@" || return 1
  if [ "$restored" = "$CONFIG_RESTORED" ] || plugin_running; then
    restart_containerd || return 1
  fi
  wait_for_plugin_exit
}
