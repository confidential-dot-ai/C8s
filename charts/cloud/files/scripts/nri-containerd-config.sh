# shellcheck shell=sh
# NRI image-policy containerd config helpers, shared by the installer, its
# pre-delete hook and the C8s host sweep. Each caller sets RESTART_COMMAND
# before it restarts containerd.

MARK_BEGIN='# BEGIN c8s-nri-image-policy (managed)'
MARK_END='# END c8s-nri-image-policy (managed)'
# Prefixes each line of the host's own NRI tables while the managed block is in.
HOST_TABLE_MARK='#c8s-nri-image-policy: '
# The installer stages its config beside config.toml under this suffix.
CANDIDATE_SUFFIX='.c8s-new'

# Succeeds when $1 holds at most one managed block: the markers once each, BEGIN
# before END, or neither.
at_most_one_managed_block() {
  awk -v b="$MARK_BEGIN" -v e="$MARK_END" '
    $0 == b { begins++; if (ends) out_of_order = 1 }
    $0 == e { ends++; if (!begins) out_of_order = 1 }
    END { exit !(begins == ends && begins <= 1 && !out_of_order) }
  ' "$1"
}

# Prints $1 as the host wrote it: without the managed block, with the host's NRI
# tables back in.
host_containerd_config() {
  awk -v b="$MARK_BEGIN" -v e="$MARK_END" -v mark="$HOST_TABLE_MARK" '
    $0 == b { in_block = 1; next }
    $0 == e { in_block = 0; next }
    in_block { next }
    index($0, mark) == 1 { print substr($0, length(mark) + 1); next }
    { print }
  ' "$1"
}

# Moves $1 over $2 so that a crash or power loss leaves either file whole: $1's
# bytes reach the disk before the rename, the rename before the next write.
replace_durably() {
  sync "$1" &&
    mv -f "$1" "$2" &&
    sync -d "$(dirname "$2")"
}

# Detached to host PID 1: the restart kills this pod's shim, and a restart in
# this pod's process tree dies with it, which on a sole control-plane node can
# wedge the cluster bootstrap.
restart_containerd() {
  echo "restarting containerd (detached via systemd-run): $RESTART_COMMAND"
  nsenter -t 1 -m -u -i -n -p -- \
    systemd-run --collect --description="c8s nri-image-policy containerd restart" \
    sh -c "$RESTART_COMMAND"
}
