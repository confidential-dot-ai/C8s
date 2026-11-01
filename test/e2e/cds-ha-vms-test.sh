#!/usr/bin/env bash
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=test/e2e/lib.sh
. "$here/lib.sh"
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT
export CDS_HA_TEST_CAPTURE=$fixture

cat > "$fixture/singleton.json" <<'JSON'
{
  "apiVersion": "kubevirt.io/v1", "kind": "VirtualMachine",
  "metadata": {"name": "cds", "namespace": "test"},
  "spec": {
    "runStrategy": "Always",
    "template": {
      "metadata": {
        "labels": {"kubevirt.io/domain": "cds"},
        "annotations": {"snp.confidential.ai/host-data": "singleton-config-hash", "igvm.confidential.ai/file": "guest-smp4.igvm"}
      },
      "spec": {"volumes": [
        {"name": "rootdisk", "persistentVolumeClaim": {"claimName": "cds-root"}},
        {"name": "opkey", "secret": {"secretName": "cds-opkey", "volumeLabel": "opkeydata"}}
      ]}
    }
  }
}
JSON

c8s() {
  case "$*" in
    'keys new '*) return 0 ;;
    'cds config new '*)
      mkdir launch
      printf 'one measured configuration for three replicas\n' > launch/cds-config.yaml ;;
    *) echo "unexpected c8s call: $*" >&2; return 1 ;;
  esac
}

kubectl() {
  if [ "$1" = -n ]; then shift 2; fi
  case "$*" in
    'apply -f -') cat > "$(mktemp "$CDS_HA_TEST_CAPTURE/service.XXXXXX")" ;;
    'get svc '*)
      local replica=${3##*-}
      [ "$replica" != ha ] || replica=10
      printf '10.43.0.%s' "$replica" ;;
    'get secret '*) printf '{"data":{"pubkey":"singleton-config"}}' ;;
    'get vm '*) cat "$CDS_HA_TEST_CAPTURE/singleton.json" ;;
    'create secret generic '*)
      local name=$4 source=${5#--from-file=pubkey=}
      cp "$source" "$CDS_HA_TEST_CAPTURE/$name.pubkey" ;;
    'delete '*|'wait '*) return 0 ;;
    'create -f '*)
      shift
      while [ "$#" -gt 0 ]; do
        [ "$1" = -f ] || return 1
        cp "$2" "$CDS_HA_TEST_CAPTURE/"
        shift 2
      done
      return 73 ;; # Stop at the VM launch boundary.
    *) echo "unexpected kubectl call: $*" >&2; return 1 ;;
  esac
}
export -f c8s kubectl

status=0
NS=test CDS_VM=cds VM=node SMP=4 NODE_CIDR=10.42.0.0/16 \
  CDS_IMAGE_MANIFEST=manifest.json CDS_ALLOWLIST_SEED=seed.json CDS_NODE_PINS=peers.json \
  bash "$here/cds-ha-vms.sh" > "$fixture/output" 2>&1 || status=$?
[ "$status" = 73 ] || { cat "$fixture/output"; fail "did not reach the VM launch boundary (exit $status)"; }

for i in 1 2 3; do
  name=cds-ha-$i
  expected=$(openssl dgst -sha256 -binary "$fixture/$name-opkey.pubkey" | base64 -w0)
  jq -e --arg name "$name" --arg expected "$expected" '
    .spec.template.metadata.annotations["snp.confidential.ai/host-data"] == $expected and
    .spec.template.metadata.annotations["igvm.confidential.ai/file"] == "guest-smp4.igvm" and
    .spec.template.metadata.labels["kubevirt.io/domain"] == $name and
    .spec.template.metadata.labels["ci.confidential.ai/cds-cluster"] == "cds-ha" and
    any(.spec.template.spec.volumes[]; .name == "opkey" and .secret.secretName == ($name + "-opkey") and .secret.volumeLabel == "opkeydata") and
    any(.spec.template.spec.volumes[]; .name == "rootdisk" and .persistentVolumeClaim.claimName == "cds-root")
  ' "$fixture/vm-$name.json" >/dev/null || fail "$name does not bind its own launch configuration"
  service=$(grep -l "^  name: $name$" "$fixture"/service.*)
  grep -q 'name: peer, port: 8444, targetPort: 8444' "$service" || fail "$name cannot accept peer discovery"
  grep -q 'name: client, port: 8443, targetPort: 8443' "$service" || fail "$name cannot accept client requests"
done
echo 'PASS: three replica VMs bind their launch configuration and expose client and peer ports'
