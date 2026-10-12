#!/usr/bin/env bash
# Exercise RKE2 rendering and its bundled containerd parser in a disposable VM's Docker daemon.
set -euo pipefail
: "${CONFOS_RELEASE:?set CONFOS_RELEASE to the pinned confos Ubuntu release}"
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
tmp=$(mktemp -d)
container=""
image="c8s-containerd-test-$$"
cleanup() {
  local result=$?
  if [ -n "$container" ]; then
    if [ "$result" != 0 ]; then
      docker exec "$container" sh -c 'cat /rke2.log; cat /var/lib/rancher/rke2/agent/containerd/containerd.log' >&2 || true
    fi
    docker rm -fv "$container" >/dev/null || result=1
  fi
  docker image rm "$image" >/dev/null 2>&1 || true
  rm -rf -- "$tmp"
  return "$result"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

pin() { sed -n "s/^$1=\"\([^\"]*\)\"$/\1/p" node-guest-image/c8s/mkosi.sync; }
rke2=$(pin RKE2_VERSION)
[[ "$rke2" =~ ^v[0-9]+\.[0-9]+\.[0-9]+\+rke2r[0-9]+$ ]]
timeout 300 gh release download "$rke2" --repo rancher/rke2 --dir "$tmp" \
  --pattern rke2.linux-amd64.tar.gz --pattern rke2-images-core.linux-amd64.tar.zst
printf '%s  %s\n' "$(pin RKE2_TARBALL_SHA256)" "$tmp/rke2.linux-amd64.tar.gz" \
  "$(pin RKE2_IMAGES_CORE_SHA256)" "$tmp/rke2-images-core.linux-amd64.tar.zst" | sha256sum -c -
mkdir "$tmp/build"
tar xzf "$tmp/rke2.linux-amd64.tar.gz" -C "$tmp/build" bin/rke2
timeout 300 docker build -q -t "$image" --build-arg "RELEASE=$CONFOS_RELEASE" -f - "$tmp/build" <<'EOF'
ARG RELEASE
FROM ubuntu:${RELEASE}
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
    ca-certificates iptables iproute2 kmod procps
COPY bin/rke2 /usr/local/bin/rke2
CMD ["sleep", "infinity"]
EOF
container=$(docker run -d --privileged "$image")
config_dir=/var/lib/rancher/rke2/agent/etc/containerd
containerd_bin=/var/lib/rancher/rke2/bin/containerd
docker exec "$container" mkdir -p "$config_dir" /var/lib/rancher/rke2/agent/images
docker cp node-guest-image/c8s/mkosi.extra/var/lib/rancher/rke2/agent/etc/containerd/. "$container:$config_dir/"
docker cp "$tmp/rke2-images-core.linux-amd64.tar.zst" "$container:/var/lib/rancher/rke2/agent/images/"

render() {
  docker exec "$container" rm -f "$config_dir/config.toml"
  docker exec -d "$container" sh -c 'exec rke2 server --cni=none --snapshotter=native > /rke2.log 2>&1'
  for _ in $(seq 1 120); do
    if docker exec "$container" test -s "$config_dir/config.toml" &&
       docker exec "$container" test -x "$containerd_bin"; then return; fi
    sleep 1
  done
  echo 'RKE2 config and containerd binary were not ready within 120 seconds' >&2
  return 1
}
dump() {
  docker exec "$container" "$containerd_bin" \
    --config "$config_dir/config.toml" config dump
}
render
containerd_bin=$(docker exec "$container" readlink -f "$containerd_bin")
if ! dump > "$tmp/effective.toml"; then
  cat "$tmp/effective.toml" >&2
  exit 1
fi
docker cp "$container:$config_dir/config.toml" "$tmp/config.toml"
python3 - "$tmp" <<'PY'
import pathlib
import sys
import tomllib

root = pathlib.Path(sys.argv[1])
config = tomllib.loads((root / "config.toml").read_text())
assert config["version"] == 3, config["version"]
assert config["imports"] == ["/var/lib/rancher/rke2/agent/etc/containerd/config-v3.toml.d/*.toml"], config["imports"]
effective = tomllib.loads((root / "effective.toml").read_text())
plugins = effective["plugins"]
assert plugins["io.containerd.nri.v1.nri"]["disable"] is False
validator = plugins["io.containerd.nri.v1.nri"]["default_validator"]
assert validator["enable"] is True
assert validator["required_plugins"] == ["nri-image-policy"]
PY
echo 'PASS: RKE2-generated config loads the required NRI validator'

docker restart --time 5 "$container" >/dev/null
cat > "$tmp/config-v3.toml.tmpl" <<'EOF'
{{/* c8s-containerd-prep:managed-template */}}
imports = ["/var/lib/rancher/rke2/agent/etc/containerd/config-v3.toml.d/*.toml"]

{{ template "base" . }}
EOF
docker cp "$tmp/config-v3.toml.tmpl" "$container:$config_dir/"
render
if dump > "$tmp/duplicate.log" 2>&1; then
  echo 'containerd accepted the historical duplicate-imports template' >&2
  exit 1
fi
cat "$tmp/duplicate.log"
grep -Fq 'key imports is already defined' "$tmp/duplicate.log"
echo 'PASS: containerd rejects the historical duplicate-imports template'
