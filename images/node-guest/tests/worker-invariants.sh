#!/usr/bin/env bash
# Worker image invariants, run by `make test-node-guest-image-invariants`:
# the kernel fragment, the boot gates, the programs the image bakes and the
# staging dependency of every host unit. Each refusal names the rule it
# breaks, as [rule], and worker-invariants-test.sh mutates one input per rule.
#
# The measured runtime wrapper's identity is checked in Go, where the
# wrapper's compiled path and the containerd drop-in parse
# (images/node-guest/worker/profile_test.go).
#
# CONFOS_DIR names the pinned confidential-os-builder checkout the image
# builds with; the fragment is compared against that tree's gpu fragment.
set -euo pipefail

IMAGE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CONFOS_DIR=${CONFOS_DIR:-$(cd "$IMAGE_DIR/../.." && pwd)/confos}
FRAGMENT=$IMAGE_DIR/kernel/c8s.config
SNAPSHOT=$IMAGE_DIR/kernel/config-x86_64-c8s.snapshot

# The boot gates that may run before the worker document is staged: each is a
# oneshot containerd waits for, and each either powers the worker off or is a
# no-op. Every other host unit the image bakes must wait for staging, so a new
# exemption is an edit here.
BOOT_GATES=(apparmor-enforce.service c8s-modules-latch.service
            scratch-enforce.service gpu-cc-enforce.service
            containerd-data-disk.service models-disk.service)
# The programs the image bakes: its own boot gates. The build stages the
# pinned RKE2 runtime binaries beside them.
BAKED_PROGRAMS=(apparmor-enforce.sh containerd-data-disk.sh gpu-cc-enforce.sh
                models-disk.sh scratch-enforce.sh worker-stage.sh)

# fail RULE MESSAGE
fail() { echo "::error::[$1] $2"; exit 1; }
# holds LIST ITEM — ITEM is one of the space-separated words of LIST.
holds() { case " $1 " in *" $2 "*) return 0 ;; *) return 1 ;; esac; }
# effective_lines FILE — the kernel settings FILE states, as a sorted set.
effective_lines() { grep -E '^CONFIG_|^# CONFIG_.* is not set$' "$1" | sort -u; }

[ -f "$CONFOS_DIR/kernel/gpu.config" ] \
    || fail confos-checkout "CONFOS_DIR=$CONFOS_DIR is no confos checkout"

EXTRA=$(mktemp -d)
trap 'rm -rf -- "$EXTRA"' EXIT
bash "$IMAGE_DIR/tests/stage-worker-extra.sh" "$EXTRA"

# Only one --kernel-config-fragment is accepted per build, so the C8s
# fragment duplicates confos's gpu lines verbatim. Catch drift when
# gpu.config changes under the pinned checkout.
missing=$(comm -23 <(effective_lines "$CONFOS_DIR/kernel/gpu.config") <(effective_lines "$FRAGMENT"))
if [ -n "$missing" ]; then
  echo "::error::[gpu-fragment] ${FRAGMENT##*/} must state every setting of $CONFOS_DIR/kernel/gpu.config; missing:"
  echo "$missing"
  exit 1
fi

# gpu-cc-enforce attests every GPU once per boot, which covers every GPU only
# while the host cannot hot-add PCI devices (#669). The fragment line is the
# load-bearing control: confos fails the build when the resolved .config
# contradicts it. The snapshot leg is a second check only, because confos
# rewrites the snapshot on every build and does not fail when it is stale.
for config in "$FRAGMENT" "$SNAPSHOT"; do
  grep -qFx '# CONFIG_HOTPLUG_PCI is not set' "$config" \
      || fail pci-hotplug "${config##*/} must keep '# CONFIG_HOTPLUG_PCI is not set': gpu-cc-enforce runs only at boot"
  # Without -q, grep prints the offending lines above the error.
  if grep -E '^CONFIG_HOTPLUG_PCI[A-Z0-9_]*=[ym]$' "$config"; then
    fail pci-hotplug "${config##*/} enables the PCI hotplug symbols printed above; gpu-cc-enforce would miss a hot-added GPU"
  fi
done

# The fragment compiles modules in (confos's gpu fragment needs them), which
# the base kernel does not, so confos's 99-kspp-hardening.conf omits
# kernel.modules_disabled and the image latches the key itself.
latch=$EXTRA/etc/systemd/system/c8s-modules-latch.service
preset=$EXTRA/usr/lib/systemd/system-preset/50-worker.preset
grep -qF 'kernel.modules_disabled=1' "$latch" \
    || fail modules-latch "c8s-modules-latch.service must set kernel.modules_disabled=1: the gpu fragment compiles modules in"
grep -qx 'enable c8s-modules-latch.service' "$preset" \
    || fail modules-latch "${preset##*/} must enable c8s-modules-latch.service; an unenabled latch never runs"

# The apparmor package's own 10-apparmor.conf turns the unconfined
# restriction on, which stacks every RuntimeDefault container's profile with
# unconfined. The image's drop-in turns it off and the boot gate refuses to
# start the runtime otherwise, so a dropped drop-in, or a later sysctl.d file
# setting the key again, would surface only as a worker powering itself off at
# first boot.
key=kernel.apparmor_restrict_unprivileged_unconfined
dropin=$EXTRA/etc/sysctl.d/20-apparmor.conf
grep -qE "^$key *= *0$" "$dropin" \
    || fail apparmor-sysctl "${dropin##*/} must set $key = 0; apparmor-enforce.sh refuses to boot the worker without it"
grep -qF "/proc/sys/${key//.//}" "$EXTRA/usr/local/bin/apparmor-enforce.sh" \
    || fail apparmor-sysctl "apparmor-enforce.sh must assert /proc/sys/${key//.//}; the drop-in and the gate move together"
# sysctl.d applies files by basename order across every directory, so any
# later (or same-named) basename that sets the key wins over the drop-in.
later=$(find "$EXTRA" "$CONFOS_DIR/mkosi" -path '*/sysctl.d/*.conf' \
          -exec grep -lE "^$key *=" {} + 2>/dev/null \
        | awk -F/ -v name="${dropin##*/}" -v self="$dropin" '$NF >= name && $0 != self' || true)
if [ -n "$later" ]; then
  echo "::error::[apparmor-sysctl-order] these sysctl.d files sort after ${dropin##*/} and set $key, overriding the drop-in:"
  echo "$later"
  exit 1
fi

# A runtime or shim of the image's own would give containerd a handler that
# reaches no wrapper, whether a drop-in or RKE2's auto-detection names it
# (k3s pkg/agent/containerd/runtimes.go).
while IFS= read -r program; do
  holds "${BAKED_PROGRAMS[*]}" "${program##*/}" \
      || fail baked-program "the worker image bakes ${program#"$EXTRA"}, which is no boot gate of its own; only the measured wrapper may serve ordinary pods"
done < <(find "$EXTRA" -type f \( -path '*/bin/*' -o -path '*/sbin/*' -o -name 'containerd-shim-*' \))

# The image's own programs hold no shellcheck warning: a quoting or test
# mistake in a boot gate powers the worker off.
shellcheck -S warning "$EXTRA"/usr/local/bin/*.sh \
    || fail baked-program-lint "shellcheck refuses a program the worker image bakes (above)"

# A host service holding node secrets must not run before the measured worker
# document is staged: Requires= propagates a staging failure and After=
# orders it. Only the boot gates run earlier.
units=$EXTRA/etc/systemd/system
containerd=$units/containerd.service
containerd_waits_for=$(sed -n 's/^\(Requires\|After\)=//p' "$containerd" | tr '\n' ' ')
for gate in "${BOOT_GATES[@]}"; do
  holds "$containerd_waits_for" "$gate" \
      || fail boot-gate "containerd.service must wait for the boot gate $gate"
  grep -qx 'Type=oneshot' "$units/$gate" \
      || fail boot-gate "the boot gate $gate runs before staging, so it must be a oneshot"
done
baked_units=""
for unit in "$units"/*; do
  name=${unit##*/}
  baked_units="$baked_units $name"
  case "$name" in
    *.service) ;;
    *) fail unit-kind "the worker image bakes the $name unit, which this gate's staging rule does not cover" ;;
  esac
  if [ "$name" = worker-stage.service ]; then
    grep -qx 'FailureAction=poweroff-force' "$unit" \
        || fail staging-poweroff "$name must power the worker off when staging fails"
    continue
  fi
  if holds "${BOOT_GATES[*]}" "$name"; then
    continue
  fi
  if ! grep -qE '^Requires=.*worker-stage[.]service' "$unit" \
     || ! grep -qE '^After=.*worker-stage[.]service' "$unit"; then
    fail staging-dependency "$name must require and start after worker-stage.service"
  fi
done
for required in worker-stage.service containerd.service kubelet.service attest-proxy.service; do
  holds "$baked_units" "$required" \
      || fail baked-units "the worker image must bake $required"
done

echo "all worker image invariants hold"
