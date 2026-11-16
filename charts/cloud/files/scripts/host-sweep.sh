# shellcheck shell=sh
# C8s host sweep — run after the shared nri-containerd-config.sh and
# nri-plugin-removal.sh by `c8s uninstall` as a privileged init container on
# every linux node (a short-lived kubectl-applied DaemonSet; see
# cmd/c8s/uninstall.go). These bytes are an interface: the chart pins them
# into the served allowlist (c8s.argvPinnedEntries) and the CLI replays the
# release's pinned bytes at uninstall, so edits stay admissible across
# CLI/chart version skew.
#
# This sweep is the only thing that takes the plugin off a node. `helm
# uninstall` deletes the release resources, and the mesh's preStop strips its
# traffic interception within the pod's termination grace period, keeping the
# fail-closed guard by design. Neither knows about the C8s-side artifacts
# (a containerd config template an earlier install managed, `c8s volume attach`
# LIO disks). It runs on every uninstall, whatever the release's shape:
# leftovers may come from a previous install of a different shape, which this
# release's values cannot see.
#
# Fatal vs warn: a plugin this sweep cannot take off containerd fails the
# sweep (the CLI then keeps the DaemonSet so its logs survive), after every
# other step ran. Per-object netfilter failures warn and
# continue; a host with no iptables at all fails the sweep at the end, after
# every other step ran. A `c8s volume attach` disk that is in use warns and
# stays; one whose use cannot be read, or an idle one that will not tear
# down, stays and fails the sweep the same way.
#
# Env (all required unless noted; set by `c8s uninstall` from the release's
# computed values):
#   HOST_CONTAINERD_DIR    — host containerd config directory
#   RESTART_COMMAND        — host runtime restart, run detached via systemd-run
#   NRI_PLUGIN_DIR         — NRI plugin directory (nriImagePolicy.hostPaths.pluginDir)
#   NRI_CONFIG_DIR         — plugin config dir (nriImagePolicy.hostPaths.configDir)
#   NRI_RUNTIME_DIR        — plugin runtime dir
#   NRI_CACHE_DIR          — plugin cache dir

# The admission pin covers argv, not PATH resolution.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset IFS ENV CDPATH

set -eu

# The plugin's own runtime dir, set here rather than read from the environment:
# an older `c8s uninstall` replaying this script sets no variable for it. A Go
# test holds it to EnforcerRuntimeDir in internal/cmds/nri-image-policy.
ENFORCER_RUNTIME_DIR=/run/c8s-enforcer

# Leaves a directory another NRI plugin's file still sits in.
remove_dir_if_empty() {
  rmdir "$1" 2>/dev/null || :
}

echo "==> c8s host sweep starting"

sweep_failed=0

# == Phase 1: containerd configuration templates =============================

# A containerd config template an earlier install managed: sentinel-marked,
#    it would re-add an import for a drop-in nothing writes now. A template
#    without the sentinel is the operator's and stays. The prep lock beside
#    it goes too.
SENTINEL='c8s-containerd-prep:managed-template'
for t in config-v3.toml.tmpl config.toml.tmpl; do
  f="${CONTAINERD_DIR}/${t}"
  [ -f "$f" ] || continue
  if grep -qF "$SENTINEL" "$f"; then
    rm -f "$f"
    echo "managed containerd template removed: $f"
  else
    echo "leaving ${t}: not the c8s-managed template"
  fi
done
rm -f "${CONTAINERD_DIR}/.c8s-containerd-prep.lock"

# == Phase 2: the NRI image-policy plugin ====================================
# Every plugin binary an install of any shape wrote, then, once no plugin
#    runs, its host artifacts. The rm -rf targets must carry the plugin's own
#    directory name — the values come from the release and a bare parent dir
#    (/var/run, /var/lib) is never deleted.
if remove_plugin_from_containerd "/host${NRI_PLUGIN_DIR}"/*-nri-image-policy; then
  rm -f "/host${NRI_CONFIG_DIR}/image-policy.yaml"
  rm -f "/host${NRI_CONFIG_DIR}/cds-address"
  rm -f "/host${NRI_CONFIG_DIR}/cds.json"
  case "$NRI_RUNTIME_DIR" in
    */nri-image-policy) rm -rf "/host${NRI_RUNTIME_DIR}" ;;
    *) [ ! -e "/host${NRI_RUNTIME_DIR}" ] || echo "leaving NRI runtime dir with a custom name: ${NRI_RUNTIME_DIR}" ;;
  esac
  case "$NRI_CACHE_DIR" in
    */nri-image-policy) rm -rf "/host${NRI_CACHE_DIR}" ;;
    *) [ ! -e "/host${NRI_CACHE_DIR}" ] || echo "leaving NRI cache dir with a custom name: ${NRI_CACHE_DIR}" ;;
  esac
  rm -rf "/host${ENFORCER_RUNTIME_DIR}"
  remove_dir_if_empty "/host${NRI_CONFIG_DIR}"
  remove_dir_if_empty "/host${NRI_PLUGIN_DIR}"
else
  echo "ERROR: the NRI image-policy plugin is not off this node; its artifacts stay for the next sweep" >&2
  sweep_failed=1
fi

# `c8s volume attach` LIO loopback disks. attach builds them through configfs
#    (internal/cmds/volume/attach.go) and nothing in the release removes them,
#    so a disk serving a volume's image outlived the uninstall and the next
#    install's attach of that name refused until someone ran detach. Only what
#    attach builds is touched: a backstore under its fileio_0 HBA whose unit
#    serial is exactly c8s-vol-<backstore name>, and the loopback target whose
#    WWN attach derives from that serial (loopbackWWN). Teardown follows
#    Attacher.Detach: LUN mapping, LUN, portal group and target, then the
#    backstore, which LIO refuses to release while a LUN references it.
#    A disk is left in place and named when the disk or a partition of it has
#    a holder (volumed's dm-crypt, a partition mapping), is mounted in any
#    mount namespace on the host (one /proc/<pid>/mountinfo per distinct
#    namespace, matched by device number or, for filesystems such as btrfs
#    that report an anonymous one, by mount source), or is active swap:
#    removing it unbinds the device under its user. A process holding the raw device open with no mount or
#    holder is invisible here, as it is to Detach. State the check cannot read
#    fails the sweep and the disk stays. Runs in the host's mount and PID
#    namespaces, where configfs is mounted and every process is visible.
#    Args: configfs mount, sysfs mount, procfs mount.
# shellcheck disable=SC2016
lio_sweep_script='
set -u
LC_ALL=C
export LC_ALL
cfg="$1/target"
sys="$2"
proc="$3"
hba="$cfg/core/fileio_0"
[ -d "$hba" ] || exit 0
failed=0
sha=""
mnt_devs=""
mnt_scanned=0

# The device numbers and sources mounted anywhere on the host, read once and
# only when a c8s backstore exists: one mountinfo per distinct mount
# namespace. A PID whose ns/mnt link cannot be read has exited (zombies and
# exiting tasks have no namespaces, and their mountinfo fails to read too) and
# holds nothing; a live one whose mountinfo cannot be read is an unknown, not
# "unmounted". A procfs without self/mountinfo is no procfs to scan.
scan_mounts() {
  [ "$mnt_scanned" = 0 ] || return 0
  mnt_scanned=1
  if [ ! -r "$proc/self/mountinfo" ]; then
    mnt_devs="UNREADABLE $proc/self/mountinfo"
    return 0
  fi
  mnt_devs=$(
    seen=" "
    for pid in "$proc"/[0-9]*; do
      ns=$(readlink "$pid/ns/mnt" 2>/dev/null) || continue
      case "$seen" in *" $ns "*) continue ;; *) ;; esac
      if cat "$pid/mountinfo" 2>/dev/null; then
        seen="$seen$ns "
      elif readlink "$pid/ns/mnt" >/dev/null 2>&1; then
        echo "UNREADABLE $pid/mountinfo"
      fi
    done | awk "\$1 == \"UNREADABLE\" { print; next }
      { if (!seen[\$3]++) print \$3
        for (i = 7; i < NF; i++) if (\$i == \"-\") { if (!seen[\$(i + 2)]++) print \$(i + 2); break } }"
  )
}

for store in "$hba"/*; do
  [ -d "$store" ] || continue
  name=${store##*/}
  # A c8s volume name: dns-1123 label of at most 12 characters (names.go).
  case "$name" in
    *[!a-z0-9-]*|-*|*-) continue ;;
  esac
  [ "${#name}" -le 12 ] || continue
  serial=$(cat "$store/wwn/vpd_unit_serial" 2>/dev/null) || continue
  serial=${serial#"T10 VPD Unit Serial Number: "}
  [ "$serial" = "c8s-vol-$name" ] || continue

  if [ -z "$sha" ]; then
    if command -v sha256sum >/dev/null 2>&1; then
      sha=sha256sum
    elif command -v busybox >/dev/null 2>&1 && busybox sha256sum </dev/null >/dev/null 2>&1; then
      sha="busybox sha256sum"
    else
      echo "ERROR: no sha256sum on this host — cannot locate the loopback target of c8s volume $name" >&2
      failed=1
      continue
    fi
  fi
  wwn="naa.5$(printf "%s" "c8s-vol-$name" | $sha | cut -c1-15)"
  target="$cfg/loopback/$wwn"
  tpgt="$target/tpgt_1"

  held=""
  unknown=""
  if [ -e "$tpgt/address" ]; then
    if addr=$(cat "$tpgt/address" 2>/dev/null); then
      for blk in "$sys/class/scsi_device/$addr:0/device/block"/*; do
        [ -d "$blk" ] || continue
        # The disk, then each partition on it.
        for part in "$blk" "$blk"/*; do
          [ "$part" = "$blk" ] || [ -f "$part/partition" ] || continue
          pname=${part##*/}
          for h in "$part"/holders/*; do
            if [ -e "$h" ] || [ -L "$h" ]; then held="$held ${h##*/}"; fi
          done
          if ! devno=$(cat "$part/dev" 2>/dev/null); then
            unknown="$unknown $part/dev"
            continue
          fi
          scan_mounts
          for m in $mnt_devs; do
            case "$m" in
              UNREADABLE) ;;
              "$devno"|"/dev/$pname") held="$held $pname(mounted)" ;;
              *) ;;
            esac
          done
          if [ -e "$proc/swaps" ]; then
            if swaps=$(cat "$proc/swaps" 2>/dev/null); then
              for s in $(printf "%s\n" "$swaps" | awk "NR > 1 { print \$1 }"); do
                if [ "$s" = "/dev/$pname" ]; then held="$held $pname(swap)"; fi
              done
            else
              unknown="$unknown $proc/swaps"
            fi
          fi
        done
      done
      case "$mnt_devs" in
        *UNREADABLE*) unknown="$unknown $(printf "%s\n" "$mnt_devs" | awk "\$1 == \"UNREADABLE\" { print \$2 }")" ;;
        *) ;;
      esac
    else
      unknown="$unknown $tpgt/address"
    fi
  fi
  if [ -n "$unknown" ]; then
    echo "ERROR: leaving c8s volume $name attached: cannot tell whether its disk is in use (unreadable:$unknown)" >&2
    failed=1
    continue
  fi
  if [ -n "$held" ]; then
    echo "warning: leaving c8s volume $name attached: its disk is in use by$held — release it, then run: c8s volume detach $name" >&2
    continue
  fi

  if [ -d "$tpgt" ]; then
    for l in "$tpgt"/lun/lun_0/*; do
      if [ -L "$l" ]; then rm -f "$l"; fi
    done
    [ ! -d "$tpgt/lun/lun_0" ] || rmdir "$tpgt/lun/lun_0" 2>/dev/null || :
    rmdir "$tpgt" 2>/dev/null || :
  fi
  [ ! -d "$target" ] || rmdir "$target" 2>/dev/null || :
  # Best effort, as in Detach: some kernels refuse to un-enable a device, and
  # the rmdir is what releases it.
  { echo 0 > "$store/enable"; } 2>/dev/null || :
  rmdir "$store" 2>/dev/null || :
  if [ -e "$store" ] || [ -e "$target" ]; then
    echo "ERROR: could not detach c8s volume $name (backstore $store, target $target)" >&2
    failed=1
  else
    echo "c8s volume LIO disk detached: $name ($wwn)"
  fi
done
exit "$failed"
'

if ! nsenter -t 1 -m -u -i -n -p -- sh -c "$lio_sweep_script" lio-sweep /sys/kernel/config /sys /proc; then
  echo "ERROR: c8s volume LIO sweep failed — an attached volume disk is left serving its image" >&2
  sweep_failed=1
fi

# ARMTLS-MESH netfilter state. The mesh's preStop removes only the traffic
#    interception (--keep-guard keeps the fail-closed filter chains and their
#    ipsets by design), and a mesh pod that never ran preStop leaves
#    everything — including the OUTPUT redirect that sends host-originated
#    pod traffic to a dead proxy port. Names are the mesh's fixed contract
#    (internal/cmds/armtlsmesh/iptables.go; pinned by a Go test). Both address
#    families; jumps before chains, chains before ipsets (a referenced object
#    cannot be deleted). Prefers the nft frontend the mesh always wrote.
# shellcheck disable=SC2016
mesh_cleanup_script='
set -u
ipt4=""
ipt6=""
for b in iptables-nft iptables; do
  if command -v "$b" >/dev/null 2>&1; then ipt4="$b"; break; fi
done
for b in ip6tables-nft ip6tables; do
  if command -v "$b" >/dev/null 2>&1; then ipt6="$b"; break; fi
done
if [ -z "$ipt4" ] && [ -z "$ipt6" ]; then
  echo "ERROR: no iptables/ip6tables on this host — cannot sweep ARMTLS-MESH netfilter state" >&2
  exit 1
fi

clean_family() {
  B="$1"
  while "$B" -t nat -D OUTPUT -j ARMTLS-MESH 2>/dev/null; do :; done
  while "$B" -t nat -D PREROUTING -j ARMTLS-MESH-PREROUTING 2>/dev/null; do :; done
  while "$B" -t filter -D FORWARD -j ARMTLS-MESH-CW 2>/dev/null; do :; done
  while "$B" -t filter -D FORWARD -j ARMTLS-MESH-CW-EGRESS 2>/dev/null; do :; done
  for spec in nat:ARMTLS-MESH nat:ARMTLS-MESH-PREROUTING filter:ARMTLS-MESH-CW filter:ARMTLS-MESH-CW-EGRESS
  do
    t=${spec%%:*}
    c=${spec#*:}
    if "$B" -t "$t" -L "$c" -n >/dev/null 2>&1; then
      if "$B" -t "$t" -F "$c" && "$B" -t "$t" -X "$c"; then
        echo "$B $t chain removed: $c"
      else
        echo "warning: could not remove $B $t chain $c" >&2
      fi
    fi
  done
}
[ -z "$ipt4" ] || clean_family "$ipt4"
[ -z "$ipt6" ] || clean_family "$ipt6"

if command -v ipset >/dev/null 2>&1; then
  for s in ARMTLS-MESH-PODS ARMTLS-MESH-PODS6 ARMTLS-MESH-LOCAL-PODS ARMTLS-MESH-LOCAL-PODS6 ARMTLS-MESH-CW-PODS ARMTLS-MESH-CW-PODS6
  do
    for n in "$s" "$s-TMP"; do
      ipset destroy "$n" 2>/dev/null && echo "ipset removed: $n" || true
    done
  done
else
  echo "warning: no ipset on this host — any ARMTLS-MESH-* ipsets are left in place" >&2
fi
exit 0
'

if ! nsenter -t 1 -m -u -i -n -p -- sh -c "$mesh_cleanup_script"; then
  echo "ERROR: ARMTLS-MESH netfilter sweep failed — stale chains redirect host-originated pod traffic to a dead port" >&2
  sweep_failed=1
fi

if [ "$sweep_failed" = "1" ]; then
  echo "==> c8s host sweep finished WITH FAILURES (see above)" >&2
  exit 1
fi
echo "==> c8s host sweep finished"
