#!/usr/bin/env bash
# images/cds-guest invariants gate, run by the node-guest-image-lint workflow.
# Runs from the repo root against the pinned confos checkout at ./confos.

# shellcheck disable=SC2016 # Single quotes hold literal match strings.
set -euo pipefail

image=images/cds-guest
build="$image/build"
profile="$image/cds"
unit="$profile/mkosi.extra/etc/systemd/system/cds.service"
preset="$profile/mkosi.extra/usr/lib/systemd/system-preset/50-cds.preset"
finalize="$profile/mkosi.finalize"
node_finalize=node-guest-image/c8s/mkosi.finalize
staged=/run/confai/operator-pubkey

# The composition is confos's base + attest and this profile, in that order.
# RKE2, a container runtime and the kubelet reach an image only through the
# c8s profile, an interactive shell only through ssh or dev, and forwarded
# arguments would let a caller this gate never sees add any of them.
mapfile -t profiles < <(grep -oE -- '--profile [a-z0-9-]+' "$build" | awk '{print $2}')
if [ "${profiles[*]}" != "attest cds" ]; then
  echo "::error::$build must enable the attest and cds profiles in that order, got: ${profiles[*]:-none}"
  exit 1
fi
profile_dir=$(grep -oE -- '--profile-dir "[^"]+"' "$build" | sed 's/.*"\(.*\)"$/\1/')
if [ "${profile_dir##*/}" != cds ]; then
  echo "::error::$build must stage a profile dir named cds, which is the name confos enables it under; got: ${profile_dir:-none}"
  exit 1
fi
if grep -qF -- '"$@"' "$build"; then
  echo "::error::$build must not forward extra arguments to confos build; the composition is fixed"
  exit 1
fi

# The CDS is one static binary, so the profile adds no package to the image
# and installs no second service: everything else would be attack surface on
# the trust root's VM.
if grep -qE '^Packages=' "$profile/mkosi.conf"; then
  echo "::error::$profile/mkosi.conf declares image packages; the CDS needs none beyond the base and attest profiles"
  exit 1
fi
# confos's SNP kernel replaces a report's REPORT_DATA with its
# measurement-register commitment, which the pinned attestation-rs refuses:
# without this flag every SNP self-report fails and the CDS never listens.
if ! grep -qE '^KernelCommandLine=.*snp_measurement_registers=off' "$profile/mkosi.conf"; then
  echo "::error::$profile/mkosi.conf must put snp_measurement_registers=off on the kernel command line"
  exit 1
fi
units=$(find "$profile/mkosi.extra" -name '*.service' -printf '%f\n' | sort | tr '\n' ' ')
if [ "$units" != "cds.service " ]; then
  echo "::error::$profile/mkosi.extra may install cds.service only, got: ${units:-none}"
  exit 1
fi
if ! grep -qx 'enable cds.service' "$preset"; then
  echo "::error::$preset must enable cds.service; an unenabled unit never runs"
  exit 1
fi
if ! grep -qF -- '"$STAGE_DIR/usr/local/bin/c8s"' "$profile/mkosi.sync"; then
  echo "::error::$profile/mkosi.sync must stage the c8s binary at /usr/local/bin/c8s, the path cds.service runs"
  exit 1
fi
# The published tag is resolved once and every blob is fetched by that
# digest, so a tag that moves mid-build cannot swap the measured bytes.
for required in 'oras manifest fetch --descriptor' '${repo}@${digest}'; do
  if ! grep -qF -- "$required" "$profile/mkosi.sync"; then
    echo "::error::$profile/mkosi.sync must resolve each published image to a digest and fetch its blobs by digest (missing: $required)"
    exit 1
  fi
done

# One verifier version for every VM in the cluster: the attester is the
# attestation-rs build .github/build-pins.json names for the node images,
# staged after the one the attest profile pins.
if ! grep -qF '.github/build-pins.json' "$build" \
   || ! grep -qF 'attestation_rs_ref' "$build" \
   || ! grep -qF -- '--sync-input "attestation-rs-ref=' "$build" \
   || ! grep -qF 'sync_input attestation-rs-ref' "$profile/mkosi.sync"; then
  echo "::error::the attestation-rs ref must flow from $build (read from .github/build-pins.json) into $profile/mkosi.sync; the CDS must not verify with another attestation-api than the nodes"
  exit 1
fi
if ! grep -qF -- '"$STAGE_DIR/usr/local/bin/attestation-api"' "$profile/mkosi.sync"; then
  echo "::error::$profile/mkosi.sync must stage that attestation-api at /usr/local/bin/attestation-api, the path attestation-api.service runs"
  exit 1
fi

# The image disables cloud-init and bakes no seed, so the host cannot hand
# the VM a configuration the measurement does not cover.
if [ ! -f "$profile/mkosi.extra/etc/cloud/cloud-init.disabled" ]; then
  echo "::error::$profile/mkosi.extra/etc/cloud/cloud-init.disabled is missing; cloud-init would run in the CDS VM"
  exit 1
fi
if grep -q -- '--cloud-init' "$build"; then
  echo "::error::$build bakes a cloud-init seed; the CDS image disables cloud-init instead"
  exit 1
fi

# A host-reachable arbitrary-REPORTDATA API would let the host borrow this
# VM's attestation for its own keys. confos copies each profile dir into its
# own tree, which rejects a link out of it, so both images carry the same
# finalize hook rather than sharing one file.
if [ ! -x "$finalize" ] || ! cmp -s "$finalize" "$node_finalize"; then
  echo "::error::$finalize must be executable and byte-identical to $node_finalize, whose content the node gate checks"
  exit 1
fi
if ! grep -qF -- '--attestation-api-url=http://127.0.0.1:8400' "$unit"; then
  echo "::error::$unit must reach the attester on the loopback bind $finalize forces"
  exit 1
fi

# The CDS config is the VM's launch file: the confos initrd stages it from
# the opkeydata disk only after binding it to the platform identity.
if ! grep -qxF "ConditionPathExists=$staged" "$unit"; then
  echo "::error::$unit must gate on the staged launch file ($staged)"
  exit 1
fi
if ! grep -qF -- "--config=$staged" "$unit"; then
  echo "::error::$unit must read the CDS config from the staged launch file ($staged)"
  exit 1
fi
if ! grep -qF "cp /opkey/pubkey /sysroot$staged" confos/mkosi/initrd/mkosi.extra/init; then
  echo "::error::confos initrd no longer stages the launch file at $staged; cds.service reads that path — update both together"
  exit 1
fi
if ! grep -qE '^Requires=.*attestation-api[.]service' "$unit" \
   || ! grep -qE '^After=.*attestation-api[.]service' "$unit"; then
  echo "::error::$unit must require the local attester: the boot self-check verifies the config against a fresh report"
  exit 1
fi

# The allowlist store and the mesh CA last one boot: the store sits in the
# unit's runtime directory, which systemd creates on tmpfs and removes again.
if ! grep -qxF 'RuntimeDirectory=cds' "$unit" \
   || ! grep -qF -- '--allowlist-db=/run/cds/' "$unit"; then
  echo "::error::$unit must keep the allowlist store in RuntimeDirectory=cds"
  exit 1
fi
if ! grep -qxF 'Restart=on-failure' "$unit" || ! grep -qxF 'StartLimitIntervalSec=0' "$unit"; then
  echo "::error::$unit must restart on failure without a start limit: the route to AMD or Intel can appear minutes after boot"
  exit 1
fi

echo "all images/cds-guest invariants hold"
