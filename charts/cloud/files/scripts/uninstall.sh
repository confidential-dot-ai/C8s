# nri-image-policy uninstaller — run as a privileged pre-delete hook, after
# the shared nri-containerd-config.sh.
#
# Reverses install.sh on a single node: restores the node's own containerd
# configuration (the sentinel-delimited block gone, the host's NRI tables
# back), restarts containerd so the plugin process exits, and deletes the
# host artifacts
# (binary, configs, cache). Idempotent — safe to re-run after a partial
# uninstall.
#
# Env (all required; chart pod spec wires them via .Values):
#   HOST_PLUGIN_PATH       — host path of the plugin binary
#   HOST_CONFIG_PATH       — host path of the runtime config
#   HOST_CDS_ADDRESS_PATH  — host path of the CDS address the config names
#   HOST_CDS_PIN_PATH      — host path of the CDS pin the config names
#   HOST_CONTAINERD_DIR    — host containerd config directory, mounted at
#                            /host<dir>
#   HOST_CACHE_DIR         — host cache directory the plugin wrote into
#   HOST_HEALTH_SOCKET     — host path of the plugin health unix socket
#   RESTART_COMMAND        — `systemctl restart …` run via nsenter into PID 1
set -eu

echo "==> nri-image-policy uninstaller starting"

CONTAINERD_DIR=/host${HOST_CONTAINERD_DIR}

# containerd renders the active config to config.toml.
main_config="$CONTAINERD_DIR/config.toml"

# 1. Put back the config the host wrote, and drop a config the installer
#    staged but never moved into place (idempotent).
config_changed=0
rm -f "$main_config$CANDIDATE_SUFFIX"
if [ -f "$main_config" ]; then
  host_containerd_config "$main_config" > "$main_config.tmp"
  if cmp -s "$main_config.tmp" "$main_config"; then
    rm -f "$main_config.tmp"
    echo "containerd config is the host's already"
  else
    mv -f "$main_config.tmp" "$main_config"
    echo "containerd config restored: $main_config"
    config_changed=1
  fi
fi

# 2. Restart containerd if we changed config. After this, NRI no longer
#    references plugin_path or default_validator; the host plugin process
#    exits and is not re-launched.
if [ "$config_changed" = "1" ]; then
  echo "restarting containerd (detached via systemd-run): ${RESTART_COMMAND}"
  # Detach the restart to host PID 1: restarting containerd kills this pod's
  # own shim, and a restart in the pod's process tree dies with it
  # mid-restart, which on a sole control-plane node can wedge the cluster
  # bootstrap. systemd-run runs it as a transient host unit that survives the
  # pod. systemctl (hence systemd-run) is always present on the host.
  # shellcheck disable=SC2086
  nsenter -t 1 -m -u -i -n -p -- \
    systemd-run --collect --description="c8s nri-image-policy containerd restart" \
    sh -c "${RESTART_COMMAND}"
fi

# 3. Remove host artifacts. Cache last so a partial-failure re-run still
#    has the binary/config to retry against.
rm -f "/host${HOST_PLUGIN_PATH}"
rm -f "/host${HOST_CONFIG_PATH}"
rm -f "/host${HOST_CDS_ADDRESS_PATH}"
rm -f "/host${HOST_CDS_PIN_PATH}"
rm -f "/host${HOST_HEALTH_SOCKET}"
rm -rf "/host${HOST_CACHE_DIR}"
echo "host artifacts removed"

echo "==> nri-image-policy uninstaller finished"
