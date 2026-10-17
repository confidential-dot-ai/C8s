#!/usr/bin/env bash
# Pre-boot half of the confidential-inference e2e on the tdx-metal lane.
#
# Builds, with the c8s under test:
#   - allowlist-seed.json, rendered the way node-guest-image/c8s/mkosi.sync
#     renders the seed it bakes, from the core images of this commit;
#   - the confidential-inference allowlist (app.json for launch-config
#     --workloads, allowlist.json for the upload after boot), linted --strict;
#   - the gateway's mutable gwstate volume and its escrow, staged as disk.img
#     on a PVC the VM attaches with serial c8s-vol-gwstate.
#
# Needs: c8s, crane, go, jq, kubectl (launcher cluster), python3, sudo.
# Env: FRONT_DOOR (cds or acme, default cds), C8S_SOURCE_DIR, c8sRef, VM, NS, GH_TOKEN (reads the org-internal
# confidential-inference images). Writes everything to $CIE_DIR.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
. "$here/pins.env"
: "${C8S_SOURCE_DIR:?}" "${c8sRef:?}" "${VM:?}" "${NS:?}" "${CIE_DIR:?}" "${GH_TOKEN:?}"
mkdir -p "$CIE_DIR"
cd "$CIE_DIR"

# confidential-inference at the pinned commit, and the release's chart inputs.
git init -q ci
git -C ci fetch -q --depth 1 "https://github.com/$CI_REPO.git" "$CI_COMMIT"
git -C ci checkout -q FETCH_HEAD
mkdir -p release
for asset in profile-values-release-values.yaml profile-values-release-staging-values.yaml release-values.yaml release-tag-commit.txt; do
  curl -fsSL --retry 4 -o "release/$asset" "https://github.com/$CI_REPO/releases/download/$CI_RELEASE/$asset"
done
[ "$(tr -d '[:space:]' < release/release-tag-commit.txt)" = "$CI_COMMIT" ] \
  || { echo "::error::$CI_RELEASE was not built from $CI_COMMIT"; exit 1; }

crane auth login ghcr.io -u "${GITHUB_ACTOR:-c8s-e2e}" --password-stdin <<<"$GH_TOKEN"

python3 -c "import yaml" 2>/dev/null || { sudo apt-get update -qq && sudo apt-get install -y -qq python3-yaml; }

# The seed render needs the Helm version the image build pins.
sync="$C8S_SOURCE_DIR/node-guest-image/c8s/mkosi.sync"
helm_version=$(sed -n 's/^HELM_VERSION="\(.*\)"$/\1/p' "$sync")
helm_sha=$(sed -n 's/^HELM_LINUX_AMD64_SHA256="\(.*\)"$/\1/p' "$sync")
rke2_version=$(sed -n 's/^RKE2_VERSION="\([^+]*\)+.*"$/\1/p' "$sync")
curl -fsSL --retry 4 -o helm.tgz "https://get.helm.sh/helm-$helm_version-linux-amd64.tar.gz"
echo "$helm_sha  helm.tgz" | sha256sum -c -
mkdir -p bin && tar -xzf helm.tgz -C bin --strip-components 1 linux-amd64/helm
export PATH="$CIE_DIR/bin:$PATH"

# The front door: cds by default, acme against pebble with FRONT_DOOR=acme.
if [ "${FRONT_DOOR:-cds}" = acme ]; then
  bash "$here/pebble.sh"
else
  printf 'FRONT_DOOR_MODE=cds\nSERVER_NAME=c8s.local\n' > front-door.env
fi
. ./front-door.env
# The gateway names its public origin in its (allowlisted) environment.
printf 'attestationReceipts:\n  evidenceBaseUrl: https://%s\n' "$SERVER_NAME" > front-door-values.yaml

render=()
for pair in image:c8s-operator cds-image:cds armtls-mesh-image:armtls-mesh; do
  flag=${pair%%:*} repo=ghcr.io/confidential-dot-ai/${pair#*:}
  render+=("--$flag-repository" "$repo" "--$flag-digest" "$(crane digest "$repo:$c8sRef")")
done
c8s node-image render --hardware-platform tdx --kube-version "$rke2_version" "${render[@]}" --output-dir node-image

# The canonical-bytes tool, linked against this c8s source.
(cd ci/tools/c8s-allowlist-canonical &&
  go mod edit -replace "github.com/confidential-dot-ai/c8s=$C8S_SOURCE_DIR" &&
  go mod tidy && go build -o "$CIE_DIR/bin/c8s-allowlist-canonical" .)

c8s_release=$(python3 -c 'import sys, yaml; print(yaml.safe_load(open(sys.argv[1]))["c8s"]["release"])' ci/release/staging/spec.yaml)
# One render for both the allowlist and the deploy: run.sh applies these
# objects, and replaces only the gateway's release-identity ConfigMap, whose
# CDS policy and operator-key pins exist only after boot. The ConfigMap is
# mounted as data, so the derived entries do not depend on its content.
chart_args=(--namespace confidential-inference --kube-version 1.32.0
  --values release/profile-values-release-values.yaml
  --values release/profile-values-release-staging-values.yaml
  --values release/release-values.yaml
  --values "$here/values.yaml"
  --values front-door-values.yaml)
printf '%s\n' "${chart_args[@]}" > chart-args
helm template confidential-inference ci/helm/confidential-inference "${chart_args[@]}" \
  | SIM_IMAGE=$SIM_IMAGE python3 "$here/patch_render.py" > manifest.yaml
python3 "$here/allowlist.py" --ci ci --manifest manifest.yaml \
  --policy "$here/policy.json" --seed node-image/allowlist-seed.json \
  --c8s "$(command -v c8s)" --c8s-release "$c8s_release" \
  --canonical-tool bin/c8s-allowlist-canonical --out-dir allowlist
jq -r '.workloads | keys[]' allowlist/allowlist.json

# The gateway writes its state as 65532 at the volume root (mode 2770).
# mkfs.ext4 -d does not copy the owner of the root itself, so root_owner
# sets it, as confidential-inference's build_state_volume.py does.
mkdir gwstate-seed
sudo chown 65532:65532 gwstate-seed
sudo chmod 2770 gwstate-seed
cat > mke2fs.conf <<'EOF'
[fs_types]
	ext4 = {
		features = has_journal,extent,huge_file,flex_bg,metadata_csum,64bit,dir_nlink,extra_isize
		root_owner = 65532:65532
	}
EOF
sudo env MKE2FS_CONFIG="$CIE_DIR/mke2fs.conf" PATH="$PATH" "$(command -v c8s)" volume create --dry-run --mutable \
  --name gwstate --source gwstate-seed --size 64Mi --path /confidential-inference/volumes/gwstate \
  --out gwstate.img --escrow-out gwstate.escrow.json --url https://unused.invalid
sudo chown "$(id -u):$(id -g)" gwstate.img gwstate.escrow.json
chmod 0666 gwstate.img

# Stage the image as disk.img on a PVC; KubeVirt attaches a filesystem PVC
# through that file.
kubectl apply -f - <<EOF
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: $VM-gwstate
  namespace: $NS
  labels: {ci.confidential.ai/managed: "true"}
spec:
  accessModes: [ReadWriteOnce]
  resources: {requests: {storage: 1Gi}}
  storageClassName: local-path
---
apiVersion: v1
kind: Pod
metadata:
  name: $VM-gwstate-copy
  namespace: $NS
  labels: {ci.confidential.ai/managed: "true"}
spec:
  nodeSelector: {kubevirt.io/tdx: "true"}
  restartPolicy: Never
  securityContext: {runAsNonRoot: true, runAsUser: 65534, fsGroup: 107, seccompProfile: {type: RuntimeDefault}}
  containers:
    - name: copy
      image: docker.io/library/busybox:1.36.1@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662
      command: [sleep, "600"]
      securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: [ALL]}}
      volumeMounts: [{name: disk, mountPath: /disk}]
  volumes: [{name: disk, persistentVolumeClaim: {claimName: $VM-gwstate}}]
EOF
kubectl -n "$NS" wait --for=condition=Ready "pod/$VM-gwstate-copy" --timeout=180s
kubectl -n "$NS" exec -i "$VM-gwstate-copy" -- sh -c 'cat > /disk/disk.img && chmod 0666 /disk/disk.img' < gwstate.img
want=$(sha256sum < gwstate.img | cut -d' ' -f1)
got=$(kubectl -n "$NS" exec "$VM-gwstate-copy" -- sha256sum /disk/disk.img | cut -d' ' -f1)
[ "$want" = "$got" ] || { echo "::error::gwstate disk.img differs from the built image"; exit 1; }
kubectl -n "$NS" delete pod "$VM-gwstate-copy" --wait=true
