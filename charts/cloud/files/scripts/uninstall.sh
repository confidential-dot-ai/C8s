# nri-image-policy uninstaller — run as a privileged pre-delete hook, after
# the shared nri-containerd-config.sh and nri-plugin-removal.sh.
#
# Reverses install.sh on a single node: removes our NRI containerd
# registration (the sentinel-delimited block in config.toml) and restores the
# host's own NRI table, deletes the plugin binary, restarts containerd until
# no plugin process is left, and deletes the remaining host artifacts.
# Idempotent: a run that stops anywhere leaves the next run able to finish.
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

# Every plugin binary an install of any shape wrote, as the host sweep does: a
# binary of an earlier install still counts as a plugin containerd launches.
remove_plugin_from_containerd "$(dirname "/host${HOST_PLUGIN_PATH}")"/*-nri-image-policy

rm -f "/host${HOST_CONFIG_PATH}"
rm -f "/host${HOST_CDS_ADDRESS_PATH}"
rm -f "/host${HOST_CDS_PIN_PATH}"
rm -f "/host${HOST_HEALTH_SOCKET}"
rm -rf "/host${HOST_CACHE_DIR}"
echo "host artifacts removed"

echo "==> nri-image-policy uninstaller finished"
