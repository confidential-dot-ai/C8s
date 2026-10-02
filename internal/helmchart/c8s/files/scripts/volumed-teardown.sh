# volumed teardown — run as a privileged pre-delete hook on every volumed node.
#
# Removes the device-mapper stack volumed opened for the pods on this node:
# unmount each C8s volume, then close the dm-verity and dm-crypt mappings
# behind it. The mappings keep the backing disk open, so a volume they cover
# cannot be reopened while they are there. Anything this hook cannot close is
# swept by volumed the next time it starts.
# Idempotent: a node with nothing open exits clean. A mapping that will not
# close exits non-zero — the alternative is an uninstall that reports success
# and leaves state no later run can reach.
#
# Names come from internal/cmds/volumed/open.go (mapperName): the mappings are
# c8s-crypt-<pod-uid>-<volume> and c8s-verity-<pod-uid>-<volume>. The mount
# source is the verity device for an immutable volume, the crypt device itself
# for a mutable one.
set -eu

# Retry budget for a close. Sized to ride out kubelet's asynchronous unmount
# while staying far inside helm's hook timeout.
CLOSE_ATTEMPTS=5
CLOSE_RETRY_SECONDS=2

# Prefixed onto the host paths below so the shipped bytes can be run against a
# fixture tree. The hook sets nothing and the prefix is empty.
root="${C8S_TEARDOWN_ROOT:-}"

echo "==> volumed teardown starting"

# 1. Unmount what the C8s devices back. /proc/mounts names the source device,
#    which holds even after kubelet has renamed the pod directory. Collect the
#    targets before unmounting any: /proc/mounts is generated as it is read, so
#    unmounting mid-scan would shift the rest of the file.
targets=""
while read -r source target _; do
  case "$source" in
  /dev/mapper/c8s-verity-* | /dev/mapper/c8s-crypt-*) targets="$targets $target" ;;
  esac
done <"$root/proc/mounts"

for target in $targets; do
  if umount "$target"; then
    echo "unmounted $target"
  else
    echo "WARNING: umount $target failed" >&2
  fi
done

# 2. Close the mappings, verity before crypt: verity is stacked on the crypt
#    device and holds it open.
closed=0
stuck=""
for dev in "$root"/dev/mapper/c8s-verity-* "$root"/dev/mapper/c8s-crypt-*; do
  [ -e "$dev" ] || continue
  name=${dev##*/}
  close=veritysetup
  case "$name" in
  c8s-crypt-*) close=cryptsetup ;;
  esac
  # kubelet tears the consumer's mount down asynchronously, so a device that
  # reads busy on the first try is often free a moment later.
  attempt=1
  while :; do
    if "$close" close "$name"; then
      closed=$((closed + 1))
      echo "closed $name"
      break
    fi
    if [ "$attempt" -ge "$CLOSE_ATTEMPTS" ]; then
      stuck="$stuck $name"
      break
    fi
    attempt=$((attempt + 1))
    sleep "$CLOSE_RETRY_SECONDS"
  done
done

echo "==> volumed teardown finished: $closed mapping(s) closed"

if [ -n "$stuck" ]; then
  # The host unmount above does not clear a consumer pod's own mount namespace,
  # so a volume still in use stays busy here. Exiting 0 would hand helm a
  # healthy hook and delete volumed, after which nothing on the node reaps
  # these and the next install cannot reopen the disk.
  echo "ERROR: still open after ${CLOSE_ATTEMPTS} attempts:$stuck" >&2
  echo "       something is still using these volumes; the host-side unmount does not" >&2
  echo "       release a consumer pod's own mount namespace. Delete the pods holding" >&2
  echo "       them and re-run the uninstall; volumed sweeps whatever is left when it" >&2
  echo "       next starts, so a reinstall clears them too." >&2
  exit 1
fi
