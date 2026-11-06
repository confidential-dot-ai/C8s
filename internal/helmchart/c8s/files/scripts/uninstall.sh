# nri-image-policy uninstaller — run as a privileged pre-delete hook.
#
# Reverses install.sh on a single node: removes our NRI containerd
# registration (drop-in file on rke2, sentinel-delimited block in
# config.toml on k8s), restarts containerd so the plugin process exits, and
# deletes the host artifacts (binary, configs, cache). Idempotent — safe to
# re-run after a partial uninstall.
#
# Env (all required; chart pod spec wires them via .Values):
#   HOST_PLUGIN_PATH       — host path of the plugin binary
#   HOST_CONFIG_PATH       — host path of the runtime config
#   HOST_CDS_ADDRESS_PATH  — host path of the CDS address the config names
#   HOST_CDS_PIN_PATH      — host path of the CDS pin the config names
#   HOST_CONTAINERD_DIR    — host containerd config directory, mounted at
#                            /host<dir>
#   CONTAINERD_CONFIG_MODE — "patch" or "dropin", matching install.sh
#   HOST_CACHE_DIR         — host cache directory the plugin wrote into
#   HOST_HEALTH_SOCKET     — host path of the plugin health unix socket
#   RESTART_COMMAND        — `systemctl restart …` run via nsenter into PID 1
set -eu

echo "==> nri-image-policy uninstaller starting"

CONTAINERD_DIR=/host${HOST_CONTAINERD_DIR}
MARK_BEGIN='# BEGIN c8s-nri-image-policy (managed)'
MARK_END='# END c8s-nri-image-policy (managed)'

# containerd/RKE2 always render the active config to config.toml.
main_config="$CONTAINERD_DIR/config.toml"

# 1. Remove the NRI containerd config (idempotent). dropin: the standalone
#    drop-in file is ours — delete it from whichever schema-versioned dir
#    it landed in (config-v3.toml.d or config.toml.d). patch: strip the
#    sentinel-delimited block. The shared `imports` line is left in place:
#    the containerd-prep initContainer owns it.
config_changed=0
if [ "${CONTAINERD_CONFIG_MODE}" = "dropin" ]; then
  for d in config-v3.toml.d config.toml.d; do
    f="$CONTAINERD_DIR/$d/nri-image-policy.toml"
    if [ -f "$f" ]; then
      rm -f "$f"
      config_changed=1
      echo "containerd drop-in removed: $f"
    fi
  done
  [ "$config_changed" = "1" ] || echo "containerd drop-in already absent"
elif [ -f "$main_config" ] && grep -qF "$MARK_BEGIN" "$main_config"; then
  awk -v b="$MARK_BEGIN" -v e="$MARK_END" '
    $0==b { skip=1; next }
    $0==e { skip=0; next }
    !skip { print }
  ' "$main_config" > "$main_config.tmp"
  mv -f "$main_config.tmp" "$main_config"
  echo "containerd config block removed from $main_config"
  config_changed=1
else
  echo "containerd config block already absent"
fi

# 2. Restart containerd if we changed config. After this, NRI no longer
#    references plugin_path or default_validator; the host plugin process
#    exits and is not re-launched.
if [ "$config_changed" = "1" ]; then
  echo "restarting containerd (detached via systemd-run): ${RESTART_COMMAND}"
  # Detach the restart to host PID 1: restarting rke2/containerd kills this
  # pod's own shim, and a restart in the pod's process tree dies with it
  # mid-restart, which on a sole control-plane node can wedge the rke2
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
