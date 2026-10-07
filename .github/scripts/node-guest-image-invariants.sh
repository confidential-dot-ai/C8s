#!/usr/bin/env bash
# node-guest-image invariants gate, run by the node-guest-image-lint workflow.
# Runs from the repo root against the pinned confos checkout at ./confos.
#
# Inputs (env):
#   CONFOS_REF   pinned confos ref the workflow resolved; names the pass line.
#   EXPECT_IMMUTABLE_ROOT  defaults to 1; requires state.d in confos's initrd.
#                Set to 0 only when inspecting a legacy confos checkout.

set -euo pipefail

: "${CONFOS_REF:?CONFOS_REF must be set}"
ngi=node-guest-image

# kernel/c8s.config must be a superset of confos kernel/gpu.config:
# only one --kernel-config-fragment is accepted per build, so the
# C8s fragment duplicates the gpu lines verbatim. Catch drift when
# gpu.config changes under the pinned CONFOS_REF.
missing=$(grep -E '^CONFIG_|^# CONFIG_.* is not set$' confos/kernel/gpu.config \
          | grep -vFxf "$ngi/kernel/c8s.config" || true)
if [ -n "$missing" ]; then
  echo "::error::$ngi/kernel/c8s.config must contain every effective line of confos kernel/gpu.config; missing:"
  echo "$missing"
  exit 1
fi

# c8s-dev.config (C8S_DEV=1 demo builds) is the union of c8s.config
# and confos dev.config, committed verbatim for the same one-fragment
# reason.
for src in "$ngi/kernel/c8s.config" confos/kernel/dev.config; do
  missing=$(grep -E '^CONFIG_|^# CONFIG_.* is not set$' "$src" \
            | grep -vFxf "$ngi/kernel/c8s-dev.config" || true)
  if [ -n "$missing" ]; then
    echo "::error::$ngi/kernel/c8s-dev.config must contain every effective line of $src; missing:"
    echo "$missing"
    exit 1
  fi
done

# CONFIG_MODULES=y is a C8s-only widening (the base kernel compiles modules
# out, which is why confos's 99-kspp-hardening.conf omits the key). The
# profile must therefore latch kernel.modules_disabled itself: the gpu
# profile's latch is absent from the GPU-less composition.
latch="$ngi/c8s/mkosi.extra/etc/systemd/system/c8s-modules-latch.service"
preset="$ngi/c8s/mkosi.extra/usr/lib/systemd/system-preset/50-rke2.preset"
if grep -qx 'CONFIG_MODULES=y' "$ngi/kernel/c8s.config"; then
  if ! grep -qF 'kernel.modules_disabled=1' "$latch"; then
    echo "::error::$ngi/kernel/c8s.config sets CONFIG_MODULES=y, so $latch must set kernel.modules_disabled=1"
    exit 1
  fi
  if ! grep -qx 'enable c8s-modules-latch.service' "$preset"; then
    echo "::error::$preset must enable c8s-modules-latch.service; an unenabled latch never runs"
    exit 1
  fi
  if ! grep -qx 'RequiredBy=rke2-server.service rke2-agent.service' "$latch"; then
    echo "::error::$latch must be RequiredBy the rke2 pair so rke2 cannot start with modules still loadable"
    exit 1
  fi
fi

# The baked NRI template contains only the generated RKE2 system floor.
# The complete chart component seed is merged into it before containerd starts;
# duplicating component digests here would drift from the rendered workloads.
policy="$ngi/c8s/image-policy.yaml.in"
[ -f "$policy" ] || { echo "::error::NRI base template $policy not found"; exit 1; }
if sed '/# BEGIN rke2 system images/,/# END rke2 system images/d' "$policy"               | grep -qE 'sha256:[a-f0-9]{64}'; then
  echo "::error::$policy has a hardcoded base digest outside the generated system base; derive core component pins from the build-time chart seed"
  exit 1
fi

# The C8s node is normally nested in an outer RKE2 cluster: its pod
# CIDR must not fall back to the outer cluster's default. Canal takes its
# pool from this setting.
rke2_config="$ngi/c8s/mkosi.extra/etc/rancher/rke2/config.yaml"
canal_config="$ngi/c8s/mkosi.extra/var/lib/rancher/rke2/server/manifests/rke2-canal-config.yaml"
rke2_pod_cidr=$(sed -n 's/^cluster-cidr:[[:space:]]*//p' "$rke2_config")
if [ -z "$rke2_pod_cidr" ] || [ "$rke2_pod_cidr" = "10.42.0.0/16" ]; then
  echo "::error::c8s RKE2 cluster-cidr must be explicit and must not overlap the outer RKE2 default"
  exit 1
fi

# armtls-mesh's cw inbound guard needs iptables-mode kube-proxy (Service DNAT
# before FORWARD) and its jumps at the head of FORWARD, ahead of Felix's.
# Localhost NodePorts stay off: they set route_localnet=1, exposing
# loopback listeners such as the attestation-api.
kube_proxy_arg() {
  awk -v want="  - $1" '/^kube-proxy-arg:/{c=1;next} c&&/^[^ ]/{c=0} c&&$0==want{f=1} END{exit !f}' "$rke2_config"
}
if ! grep -qx 'disable-kube-proxy: false' "$rke2_config" \
   || [ "$(grep -c -- '- proxy-mode=' "$rke2_config")" != 1 ] \
   || ! kube_proxy_arg proxy-mode=iptables \
   || ! kube_proxy_arg iptables-localhost-nodeports=false; then
  echo "::error::$rke2_config must run kube-proxy in iptables mode without localhost NodePorts"
  exit 1
fi
felix_config="$ngi/c8s/mkosi.extra/var/lib/rancher/rke2/server/manifests/canal-felix-config.yaml"
if ! grep -qx 'kind: FelixConfiguration' "$felix_config" \
   || ! grep -qx '  name: default' "$felix_config" \
   || ! grep -qx '  chainInsertMode: Append' "$felix_config"; then
  echo "::error::$felix_config must set Felix chainInsertMode: Append so armtls-mesh's jumps keep the chain head"
  exit 1
fi

# The sealed image denies every runc exec, so an exec probe always fails.
# The liveness override must drop the chart's exec handler, not add to it.
if ! awk '/^    calico:$/{p=1;next} p&&/^ {0,4}[^ ]/{p=0} p&&/^      livenessProbe:$/{c=1;next} c&&/^ {0,6}[^ ]/{c=0} c&&/^        exec: null$/{e=1} c&&/^        httpGet:$/{h=1} END{exit !(e&&h)}' "$canal_config"; then
  echo "::error::Canal's calico-node liveness probe must be httpGet with exec: null; exec probes cannot run on a sealed image"
  exit 1
fi

# The kubelet debugging handlers stay on (they back kubectl logs, which the
# log-reader credential exists for); exec/attach/port-forward/ephemeral
# containers are closed at the apiserver by the baked pod-exec-policy AddOn
# (its shape and expression are tested in internal/helmchart). Only the
# C8S_DEV=1 build may skip that AddOn, and only through the sync-rendered
# .skip marker.
manifests="$ngi/c8s/mkosi.extra/var/lib/rancher/rke2/server/manifests"
sync="$ngi/c8s/mkosi.sync"
if ! grep -qxF '  - enable-debugging-handlers=true' "$rke2_config"; then
  echo "::error::$rke2_config must pin kubelet-arg enable-debugging-handlers=true (kubectl logs)"
  exit 1
fi
# cred-release identities are bounded: the operator binding must not name
# cluster-admin (the baked guards must hold against the credential holder).
if grep -q 'name: cluster-admin' "$manifests/cred-release-rbac.yaml"; then
  echo "::error::$manifests/cred-release-rbac.yaml binds the operator to cluster-admin; the baked guards must hold against the credential holder"
  exit 1
fi
# Every guard AddOn — each baked admission policy and each binding of a
# cred-release group — must be staged by mkosi.sync as a reference copy on
# the read-only root, where psa-ready.sh waits for it and compares the live
# objects against it. mkosi.sync's GUARDS list is the single statement of
# what is a guard; check it against the manifests rather than repeating it.
guards=$(sed -n 's/^GUARDS="\(.*\)"$/\1/p' "$sync")
if [ -z "$guards" ] || ! grep -q 'usr/lib/confai/guards' "$sync"; then
  echo "::error::$sync must list the guard AddOns in GUARDS= and stage them under /usr/lib/confai/guards"
  exit 1
fi
for guard in $guards; do
  if [ ! -f "$manifests/$guard.yaml" ]; then
    echo "::error::$sync stages $guard.yaml as a guard but $manifests/$guard.yaml is missing"
    exit 1
  fi
done
for file in $(grep -lE 'kind: ValidatingAdmissionPolicy$|name: c8s:' "$manifests"/*.yaml); do
  guard=$(basename "$file" .yaml)
  case " $guards " in
    *" $guard "*) ;;
    *)
      echo "::error::$file is a guard (an admission policy or a cred-release group binding) but $sync GUARDS= does not stage it"
      exit 1
      ;;
  esac
done
if find "$ngi/c8s/mkosi.extra" -name '*.skip' | grep -q .; then
  echo "::error::a baked .skip marker disables an RKE2 AddOn; only mkosi.sync may render one, for dev=1"
  exit 1
fi
if ! grep -q -- '--sync-input "dev=\${C8S_DEV:-0}"' "$ngi/build" \
   || ! grep -q 'SYNC_INPUTS/dev' "$ngi/c8s/mkosi.sync"; then
  echo "::error::the dev sync-input must flow from $ngi/build (C8S_DEV) into mkosi.sync"
  exit 1
fi

# The locked image seals post-start exec at the runc boundary: every
# ordinary pod runs through the measured wrapper, which denies `runc exec`
# (c8s internal/cmds/c8srunc, docs/node-exec-mode.md). containerdcheck
# renders the effective containerd config and proves the handlers; these
# checks cover what a rendered config cannot show — that the wrapper the
# config names is the binary the build installs, and that RKE2's runtime
# auto-detection finds nothing else to add a handler for.
wrapper_dropin="$ngi/c8s/mkosi.extra/var/lib/rancher/rke2/agent/etc/containerd/config-v3.toml.d/10-c8s-runc.toml"
wrapper_path=$(sed -n 's/^[[:space:]]*BinaryName[[:space:]]*=[[:space:]]*"\(.*\)".*/\1/p' "$wrapper_dropin" | head -n1)
if [ "$wrapper_path" != "/usr/local/bin/c8s-runc" ]; then
  echo "::error::$wrapper_dropin must set the runc handler's BinaryName to /usr/local/bin/c8s-runc (got '${wrapper_path:-none}')"
  exit 1
fi
if ! grep -q "RUNC_WRAPPER_TARGET=\"\$STAGE_DIR${wrapper_path}\"" "$ngi/c8s/mkosi.sync"; then
  echo "::error::mkosi.sync must install the runtime wrapper at $wrapper_path, the path $wrapper_dropin names"
  exit 1
fi
# The wrapper execs the real runtime by absolute path; it is rke2's own runc,
# extracted at first start under the bin symlink. Both sides pin it.
real_runc=$(sed -n 's/^REAL_RUNC="\(.*\)"$/\1/p' "$ngi/c8s/mkosi.sync")
if ! grep -qE "^[[:space:]]*realRunc[[:space:]]*= \"$real_runc\"$" internal/cmds/c8srunc/c8srunc.go; then
  echo "::error::the wrapper's compiled real-runtime path and mkosi.sync's REAL_RUNC ($real_runc) have drifted"
  exit 1
fi
# RKE2 adds a runtime handler for each of these it finds on PATH
# (k3s pkg/agent/containerd/runtimes.go); none of them is wrapped.
for rt in crun nvidia-container-runtime nvidia-container-runtime-experimental \
          nvidia-container-runtime.cdi containerd-shim-lunatic-v1 \
          containerd-shim-slight-v1 containerd-shim-spin-v2 containerd-shim-wws-v1 \
          containerd-shim-wasmedge-v1 containerd-shim-wasmer-v1 containerd-shim-wasmtime-v1; do
  if find "$ngi/c8s/mkosi.extra" -name "$rt" -print -quit | grep -q .; then
    echo "::error::$ngi/c8s/mkosi.extra bakes '$rt'; RKE2 auto-detects it and adds an UNWRAPPED runtime handler"
    exit 1
  fi
done
# The gate renders RKE2's base template from a vendored copy; an RKE2 bump
# that changes it must re-vendor, or the gate checks a config the node never
# has.
base_tmpl="$ngi/c8s/containerdcheck/rke2-base-v3.toml.tmpl"
rke2_version=$(sed -n 's/^RKE2_VERSION="\(.*\)"$/\1/p' "$ngi/c8s/mkosi.sync")
if ! grep -qF "# RKE2_VERSION: $rke2_version" "$base_tmpl"; then
  echo "::error::$base_tmpl is vendored from another RKE2 than $rke2_version; re-vendor ContainerdConfigTemplateV3 from the k3s revision that RKE2 builds against and update its header"
  exit 1
fi

# The rke2-role drop-ins only bind if mkosi.sync keeps staging the
# rke2 tarball's units under /usr/local (systemd's search path);
# the systemd harness installs its fakes at the same prefix.
if ! grep -q 'tar -xzf .* -C "\$STAGE_DIR/usr/local"' "$ngi/c8s/mkosi.sync"; then
  echo "::error::mkosi.sync no longer stages rke2 under /usr/local; rke2-role drop-ins and the systemd harness depend on that unit dir"
  exit 1
fi

# The node image disables cloud-init, so the build bakes no seed.
# tests/cloud-init-disabled.sh owns the marker invariant itself.
if grep -q -- '--cloud-init' "$ngi/build"; then
  echo "::error::$ngi/build bakes a cloud-init seed; the node image disables cloud-init instead"
  exit 1
fi
# The shared TDX lifecycle originated in confidential-ci, with c8s-local
# cidata, AppArmor and private-import checks. Preserve them on re-vendor.
# Exact-source checkout/evidence stay in the automatic-only wrapper:
# staged testing must not gain a path to that privileged checkout boundary.
# 'serial: confai-scratch' rides along: scratch-enforce powers the e2e VM off without it.
tdx_runtime=.github/actions/tdx-metal-e2e/action.yml
for marker in 'hostname: cidata-bait' 'assert the host cidata disk is inert' 'serial: confai-scratch' \
              'launch.yaml' 'C8S_NODE_IMAGE=1' 'C8S_MEASUREMENTS_CONFIG=/tmp/launch-data/server.json' \
              'bash node-guest-image/tests/apparmor-runtime-test.sh' \
              'import the exact published image into a private root PVC' \
              'bash .github/scripts/tdx-image-acceptance.sh pvc'; do
  if ! grep -qF "$marker" "$tdx_runtime"; then
    echo "::error::$tdx_runtime lost '$marker': re-vendoring dropped a c8s-local patch — re-apply it"
    exit 1
  fi
done
for marker in 'image_acceptance_artifact_prefix:' 'name: ${{ needs.source.outputs.artifact }}' \
              'bash .github/scripts/tdx-image-acceptance.sh validate'; do
  if ! grep -qF "$marker" .github/workflows/tdx-image-acceptance.yml; then
    echo "::error::tdx-image-acceptance.yml lost '$marker': exact-image evidence is required"
    exit 1
  fi
done

# scratch-enforce keys on the initrd's dm mapping name; a confos rename
# would power off every healthy node. Pin the contract at the pinned ref.
if ! grep -qF '"$SCRATCH_DEV" scratch' confos/mkosi/initrd/mkosi.extra/init; then
  echo "::error::confos initrd no longer opens the scratch disk as dm 'scratch'; scratch-enforce.sh gates on that name — update both together"
  exit 1
fi

# confos's root is immutable; the profile declares the directories it
# writes at runtime in usr/lib/confai/state.d, one path per line, read the
# way the confos initrd reads them (whole line = one path, CR stripped,
# leading slash tolerated). Each must exist in the built image or the
# initrd refuses to boot: accepted if baked under mkosi.extra or created
# under mkosi.sync's stage tree.
state_confs=$(ls "$ngi"/c8s/mkosi.extra/usr/lib/confai/state.d/*.conf 2>/dev/null || true)
if [ -z "$state_confs" ]; then
  echo "::error::no state.d/*.conf under $ngi/c8s/mkosi.extra/usr/lib/confai — the immutable root needs the profile's writable dirs declared"
  exit 1
fi
state_dirs=""
while read -r d || [ -n "$d" ]; do
  d="${d%$'\r'}"; d="${d#/}"
  case "$d" in "" | \#*) continue ;; esac
  if [ ! -d "$ngi/c8s/mkosi.extra/$d" ] && ! grep -qE "\"\\\$STAGE_DIR/$d(/|\")" "$ngi/c8s/mkosi.sync"; then
    echo "::error::state.d declares '$d', which is neither baked under $ngi/c8s/mkosi.extra nor created under mkosi.sync's \$STAGE_DIR; the confos initrd refuses to boot an image whose state.d names a missing dir"
    exit 1
  fi
  state_dirs="$state_dirs $d"
done < <(cat $state_confs)

# Every runtime write outside confos's own state dirs must sit under a
# declared entry or it surfaces as EROFS mid-boot. Writers are gathered
# mechanically: absolute /etc|/opt|/usr|/srv|/boot literals on write lines
# in the profile's scripts (and the tests' FRAG* mirrors), tmpfiles.d
# create/write entries, and hostPath / local-path "paths" in the baked
# manifests. Reads that share a line with a write verb can trip this; that
# is the cheap side to err on.
covered() {
  case "$1" in /var|/var/*|/home|/home/*|/root|/root/*|/tmp|/tmp/*|/run|/run/*) return 0 ;; esac
  for d in $state_dirs; do case "$1" in "/$d"|"/$d"/*) return 0 ;; esac; done
  return 1
}
writes=$( {
  # Numeric descriptor duplication does not write a filesystem path. Remove
  # only that token; keep other redirects and write verbs on the same line.
  sed -E 's/[0-9]*[<>]&[0-9]+([[:space:];|&()]|$)/\1/g' \
      "$ngi"/c8s/mkosi.extra/usr/local/bin/*.sh "$ngi"/tests/lib.sh \
    | grep -E '(>|tee |mkdir |install |cp |mv |touch |rm |^FRAG[A-Z]*=)' \
    | grep -vE '^[[:space:]]*#' | grep -oE '/(etc|opt|usr|srv|boot)/[A-Za-z0-9_./-]+' || true
  grep -hE '^[dDfFwLpc]\+? ' "$ngi"/c8s/mkosi.extra/etc/tmpfiles.d/*.conf \
    | awk '{print $2}' | grep -E '^/(etc|opt|usr|srv|boot)/' || true
  grep -hoE '(path: *|"paths":\[")/(etc|opt|usr|srv|boot)/[A-Za-z0-9_./-]+' \
       "$ngi"/c8s/mkosi.extra/var/lib/rancher/rke2/server/manifests/*.yaml \
    | grep -oE '/(etc|opt|usr|srv|boot)/.*' || true
} | sort -u )
for w in $writes; do
  if ! covered "$w"; then
    echo "::error::$w is written at runtime (scripts / tmpfiles.d / baked manifests) but no state.d entry ($state_dirs) makes it writable under the immutable root"
    exit 1
  fi
done

# confos side. The parser this lint mirrors is pinned like the dm name
# above. Missing immutable-root support fails by default, including local
# runs; the explicit compatibility override only supports legacy inspection.
init=confos/mkosi/initrd/mkosi.extra/init
if grep -qF '/usr/lib/confai/state.d' "$init"; then
  for pin in '[ -d "/sysroot/$dir" ]' 'while read -r dir || [ -n "$dir" ]'; do
    if ! grep -qF "$pin" "$init"; then
      echo "::error::confos initrd changed how it reads state.d (missing: $pin); update this lint's parser to match, then re-pin"
      exit 1
    fi
  done
  # The NRI storage inspector classifies a state.d overlay from this boot's
  # scratch mapping, which holds only while one scratch-backed /state supplies
  # every overlay's upper layer.
  for pin in 'mount_state_backing /state' 'upperdir=/state/$2/upper'; do
    if ! grep -qF "$pin" "$init"; then
      echo "::error::confos initrd changed how state overlays are backed (missing: $pin); internal/cmds/nri-image-policy/mount_storage_linux.go reads that contract — update both together"
      exit 1
    fi
  done
elif [ "${EXPECT_IMMUTABLE_ROOT:-1}" = 1 ]; then
  echo "::error::EXPECT_IMMUTABLE_ROOT=1 but confos at CONFOS_REF $CONFOS_REF has no state.d in its initrd"
  exit 1
else
  echo "::warning::EXPECT_IMMUTABLE_ROOT=$EXPECT_IMMUTABLE_ROOT permits confos at CONFOS_REF $CONFOS_REF without state.d in its initrd; the profile's state.d declaration is inert"
fi

# The scratch base is prose in the README and a sector count in the gate;
# a bump must touch both.
if ! grep -qF 'MIN_SECTORS=125000000' "$ngi/c8s/mkosi.extra/usr/local/bin/scratch-enforce.sh" \
   || ! grep -qF 'at least 64G' "$ngi/README.md"; then
  echo "::error::scratch base drifted: scratch-enforce.sh MIN_SECTORS (64G = 125000000 sectors) and the README's 'at least 64G' must move together"
  exit 1
fi

# psa-config.yaml exempts only the platform namespaces that need privileged
# pods, and the baked policy that stops tenants relabelling their namespaces
# keeps naming `restricted`, denying, and failing closed.
psa="$ngi/c8s/mkosi.extra/etc/rancher/rke2/psa-config.yaml"
vap="$manifests/psa-level-policy.yaml"
psa_gate="$ngi/c8s/mkosi.extra/usr/local/bin/psa-ready.sh"
cred_release="$ngi/c8s/mkosi.extra/etc/systemd/system/cred-release.service"
exempt=$(sed -n '/^[[:space:]]*namespaces:/,/^[[:space:]]*[^[:space:]-]/s/^[[:space:]]*-[[:space:]]*//p' "$psa")
if [ "$exempt" != "$(printf 'kube-system\nlocal-path-storage')" ]; then
  echo "::error::$psa must exempt exactly kube-system and local-path-storage from restricted PodSecurity; got: $(echo "$exempt" | tr '\n' ' ')"
  exit 1
fi
if ! grep -q 'enforce: "restricted"' "$psa"; then
  echo "::error::$psa must default to enforce: restricted"
  exit 1
fi
if ! grep -q "== 'restricted'" "$vap" || ! grep -q "== 'latest'" "$vap"; then
  echo "::error::$vap must pin the enforce label to restricted and enforce-version to latest"
  exit 1
fi
if ! grep -q 'failurePolicy: Fail' "$vap"; then
  echo "::error::$vap must fail closed (failurePolicy: Fail)"
  exit 1
fi
if ! grep -q 'resources: \["namespaces", "namespaces/status", "namespaces/finalize"\]' "$vap" \
   || ! grep -q 'operations: \["CREATE", "UPDATE"\]' "$vap"; then
  echo "::error::$vap must match namespace CREATE and UPDATE on the resource and its status/finalize subresources, which also carry labels"
  exit 1
fi
if ! grep -q '^    - Deny$' "$vap"; then
  echo "::error::$vap binding must deny, not warn or audit"
  exit 1
fi
if [ ! -x "$psa_gate" ]; then
  echo "::error::$psa_gate must be executable"
  exit 1
fi
if ! grep -qxF 'ExecStartPre=/usr/local/bin/psa-ready.sh' "$cred_release"; then
  echo "::error::$cred_release must keep credential release behind the measured PodSecurity readiness gate"
  exit 1
fi
for required in \
  'GUARDS_DIR=${GUARDS_DIR:-/usr/lib/confai/guards}' \
  'replace --dry-run=server -f "$file"' \
  'get -f "$file"' \
  '--as="$probe_user" create --dry-run=server' \
  'probe_namespace restricted' \
  'probe_namespace privileged' \
  'probe_scope default' \
  'probe_scope kube-system'; do
  if ! grep -qF -- "$required" "$psa_gate"; then
    echo "::error::$psa_gate is missing required live admission probe: $required"
    exit 1
  fi
done

# Check requested and resolved settings, including CONFIG_LSM and duplicates.
# The build uses the same checker on its .config; apparmor-enforce.service
# separately gates RKE2 on the booted LSM/parser.
for config in c8s.config c8s-dev.config config-x86_64-c8s.snapshot; do
  bash "$ngi/check-apparmor-config.sh" "$ngi/kernel/$config"
done
grep -qE '^\s*apparmor\s*$' "$ngi/c8s/mkosi.conf" \
  || { echo "::error::$ngi/c8s/mkosi.conf must ship the apparmor package (apparmor_parser)"; exit 1; }
grep -qFx 'disable apparmor.service' "$ngi/c8s/mkosi.extra/usr/lib/systemd/system-preset/50-rke2.preset" \
  || { echo "::error::50-rke2.preset must disable apparmor.service (only the parser is wanted)"; exit 1; }

# The image renders Kubernetes integration from its staged binary at BUILD
# time. It must not revive a C8s HelmChart or boot-time values merge.
for token in '"$C8S_TARGET" node-image render' '--image-digest "$OPERATOR_DIGEST"' \
             '--kube-version "${RKE2_VERSION%%+*}"' \
             'c8s-integration.yaml' '/usr/lib/c8s/allowlist-seed.json' \
             '--cds-image-digest "$CDS_DIGEST"' '--armtls-mesh-image-digest "$MESH_DIGEST"' \
             'c8s/airgap-images.sh' '"$out/images.txt"'; do
  if ! grep -qF -- "$token" "$sync"; then
    echo "::error::$sync must stage the measured node integration (missing: $token)"
    exit 1
  fi
done
for stale in "$ngi/c8s/c8s-chart.tdx.yaml.in" "$ngi/c8s/c8s-chart.snp.yaml.in" \
             "$ngi/c8s/mkosi.extra/etc/systemd/system/c8s-chart-values.service" \
             "$ngi/c8s/mkosi.extra/usr/local/bin/c8s-chart-values.sh" \
             "$ngi/c8s/mkosi.extra/var/lib/rancher/rke2/server/manifests/c8s-chart.yaml"; do
  if [ -e "$stale" ]; then
    echo "::error::obsolete c8s Helm bootstrap artifact remains: $stale"
    exit 1
  fi
done
if grep -qE 'render_chart_helmchart|helm-install-c8s' "$sync" "$preset"; then
  echo "::error::node bootstrap must not install the c8s chart at runtime"
  exit 1
fi

# A verified role is required for both RKE2 roles and every core service.
# Conditions alone merely skip units; Requires= plus After= propagate a
# verifier/preparation failure before evaluating the role condition.
units="$ngi/c8s/mkosi.extra/etc/systemd/system"
role="$units/rke2-role.service"
role_sh="$ngi/c8s/mkosi.extra/usr/local/bin/rke2-role.sh"
require_launch_dependency() {
  local unit=$1
  if ! grep -qE '^Requires=.*rke2-role[.]service' "$unit" \
     || ! grep -qE '^After=.*rke2-role[.]service' "$unit"; then
    echo "::error::$unit must require and start after authenticated launch staging"
    exit 1
  fi
}
for rke2_role in server agent; do
  dropin="$units/rke2-$rke2_role.service.d/20-role.conf"
  require_launch_dependency "$dropin"
  if ! grep -qxF "ConditionPathExists=/run/confos/role-$rke2_role" "$dropin"; then
    echo "::error::$dropin must gate on the authenticated $rke2_role verdict"
    exit 1
  fi
done
if ! grep -qE '^Requires=.*attestation-api[.]service' "$role" \
   || ! grep -qE '^After=.*attestation-api[.]service' "$role"; then
  echo "::error::$role must require the local attester before launch verification"
  exit 1
fi
for token in 'blkid -L opkeydata' 'c8s launch-config stage' 'launch.yaml"' 'launch.yaml.sig"' 'c8s node-services prepare'; do
  if ! grep -qF -- "$token" "$role_sh"; then
    echo "::error::$role_sh lost mandatory authenticated launch staging ($token)"
    exit 1
  fi
done
if ! grep -qE '^timeout 10 mount -t iso9660 -o ro,nodev,nosuid,noexec ' "$role_sh"; then
  echo "::error::$role_sh must bound the read-only opkeydata ISO mount with timeout 10"
  exit 1
fi
if grep -qE 'joindata|defaulting to server|set_legacy_server_role' "$role_sh"; then
  echo "::error::$role_sh must not select a role from unsigned data or a missing disk"
  exit 1
fi

# Only attestation access, node inventory, credential release and volume
# opening remain host services. Core application lifecycle belongs to the
# baked Kubernetes chart, which refuses the volumed DaemonSet on a baked node.
for service in attest-proxy nri-node-ip cred-release volumed; do
  require_launch_dependency "$units/$service.service"
  if ! grep -qxF "enable $service.service" "$preset"; then
    echo "::error::$preset must enable $service.service"
    exit 1
  fi
done
for service in cds armtls-mesh armtls-mesh-iptables c8s-get-cert cds-attest allowlist-proxy c8s-nginx; do
  if [ -e "$units/$service.service" ] || grep -qxF "enable $service.service" "$preset"; then
    echo "::error::$service must run from measured Kubernetes manifests, not a duplicate host unit"
    exit 1
  fi
done
if ! grep -qF 'ExecStart=/usr/local/bin/c8s volumed --socket-dir=/var/run/nri-image-policy ' "$units/volumed.service"; then
  echo "::error::volumed must serve in the inventory socket directory the NRI plugin mounts into workload sidecars"
  exit 1
fi
if ! grep -qF 'ExecStart=/usr/local/bin/c8s attest-proxy ' "$units/attest-proxy.service"; then
  echo "::error::host attestation access must retain its fixed proxy entrypoint"
  exit 1
fi

# A host-accessible arbitrary REPORTDATA API would let a host borrow a real
# node's attestation for its own keys. The finalize hook preserves the selected
# confos attester configuration and verifies that its bind is now loopback.
finalize="$ngi/c8s/mkosi.finalize"
if [ ! -x "$finalize" ] \
   || ! grep -qF 'bind = "127.0.0.1:8400"' "$finalize" \
   || ! grep -qF '"$BUILDROOT/etc/attestation-api/config.toml"' "$finalize"; then
  echo "::error::mkosi.finalize must force and verify the attester's loopback bind"
  exit 1
fi

echo "all node-guest-image invariants hold at CONFOS_REF $CONFOS_REF"
