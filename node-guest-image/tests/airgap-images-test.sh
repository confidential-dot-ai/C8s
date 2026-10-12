#!/usr/bin/env bash
# Real ORAS + OCI fixture: verify complete index preservation, imported names,
# verified cache reuse, deterministic archives and rejection of unpinned/empty
# image lists offline.
set -euo pipefail
TESTS_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
for tool in oras jq python3 tar; do command -v "$tool" >/dev/null; done
REAL_ORAS=$(command -v oras)
export REAL_ORAS
# shellcheck source=node-guest-image/c8s/image-source.sh
source "$TESTS_DIR/../c8s/image-source.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
OCI_SOURCE="$work/source"
export OCI_SOURCE
mkdir -p "$work/bin" "$OCI_SOURCE/blobs/sha256"
python3 - "$OCI_SOURCE" > "$work/images.txt" <<'PYFIXTURE'
import hashlib, json, pathlib, sys
root = pathlib.Path(sys.argv[1])
def raw(data, media_type):
    digest = hashlib.sha256(data).hexdigest()
    (root / "blobs/sha256" / digest).write_bytes(data)
    return {"mediaType": media_type, "digest": "sha256:" + digest, "size": len(data)}
def blob(value, media_type):
    return raw(json.dumps(value, sort_keys=True, separators=(",", ":")).encode(), media_type)
children = []
for architecture in ("amd64", "arm64"):
    platform = {"architecture": architecture, "os": "linux"}
    config = blob({"architecture": architecture, "os": "linux", "config": {},
                   "rootfs": {"type": "layers", "diff_ids": []}},
                  "application/vnd.oci.image.config.v1+json")
    layer = raw(("layer-" + architecture).encode() * 512, "application/vnd.oci.image.layer.v1.tar")
    manifest = blob({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                     "config": config, "layers": [layer]}, "application/vnd.oci.image.manifest.v1+json")
    manifest["platform"] = platform
    if architecture == "arm64":
        # A nested index: its manifest is reachable only through it.
        manifest = blob({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
                         "manifests": [manifest]}, "application/vnd.oci.image.index.v1+json")
        manifest["platform"] = platform
    children.append(manifest)
index = blob({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
              "manifests": children}, "application/vnd.oci.image.index.v1+json")
index["annotations"] = {"org.opencontainers.image.ref.name": "fixture"}
(root / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}')
(root / "index.json").write_text(json.dumps({"schemaVersion": 2, "manifests": [index]}))
print("registry.example.com/core@" + index["digest"])
PYFIXTURE
# Replace only the registry transport. The production archiver and actual
# ORAS copying/digest verification run unchanged against a local OCI layout.
cat > "$work/bin/oras" <<'SHIM'
#!/usr/bin/env bash
set -euo pipefail
[[ $1 != cp ]] || echo "${@: -1}" >> "$ORAS_LOG"
if [[ ${2:-} == --from-oci-layout ]]; then
    exec "$REAL_ORAS" "$@"
fi
[[ $# == 4 && $1 == cp && $2 == --to-oci-layout ]]
[[ $3 == registry.example.com/core@* ]]
exec "$REAL_ORAS" cp --from-oci-layout --to-oci-layout "$OCI_SOURCE@${3##*@}" "$4"
SHIM
chmod +x "$work/bin/oras"
export PATH="$work/bin:$PATH"
ORAS_LOG="$work/oras.log"
export ORAS_LOG
copies() { [[ -f "$ORAS_LOG" ]] && wc -l < "$ORAS_LOG" || echo 0; }
script="$TESTS_DIR/../c8s/airgap-images.sh"
bash "$script" "$work/images.txt" "$work/cache" "$work/first"
[[ $(copies) == 1 ]]
# A verified cache is reused without copying and archives identically.
bash "$script" "$work/images.txt" "$work/cache" "$work/second"
[[ $(copies) == 1 ]]
cmp "$work/first/c8s-0.tar" "$work/second/c8s-0.tar"
[[ $(tar -tf "$work/first/c8s-0.tar" | grep -c '^blobs/sha256/.') == 8 ]]
# Damaged blobs, stray entries or a tag fresh copies never write force a
# clean recopy.
cached="$work/cache/oci-$(cut -d@ -f2 "$work/images.txt" | cut -d: -f2)"
edit_tag() {
    jq "(.manifests[] | select(.annotations[\"org.opencontainers.image.ref.name\"] == \"measured\")) |= ($1)" \
        "$cached/index.json" > "$work/index.json"
    mv "$work/index.json" "$cached/index.json"
}
damage() {
    local blobs=("$cached"/blobs/sha256/*)
    case $1 in
        corrupt) sed -i s/amd64/amd65/ "$(grep -l amd64 "${blobs[@]}" | head -1)" ;;
        layer) sed -i s/layer-arm64/layer-arm65/ "$(grep -l layer-arm64 "${blobs[@]}")" ;;
        missing) rm "${blobs[0]}" ;;
        truncated) : > "${blobs[0]}" ;;
        stray) echo stray > "$cached/blobs/sha256/$(printf stray | sha256sum | cut -d' ' -f1)" ;;
        emptydir) mkdir "$cached/blobs/sha512" ;;
        untagged) edit_tag '.annotations = {}' ;;
        octet) edit_tag '.mediaType = "application/octet-stream"' ;;
        extrakey) edit_tag '.platform = {"architecture": "amd64", "os": "linux"}' ;;
    esac
}
for step in corrupt layer missing truncated stray emptydir untagged octet extrakey; do
    before=$(copies)
    damage "$step"
    bash "$script" "$work/images.txt" "$work/cache" "$work/recopied"
    [[ $(copies) == $((before + 1)) ]] || { echo "reused a damaged cache: $step" >&2; exit 1; }
    cmp "$work/first/c8s-0.tar" "$work/recopied/c8s-0.tar"
done
# The archived oci-layout is fixed, so a damaged cached one never reaches it.
echo '{"imageLayoutVersion":"9"}' > "$cached/oci-layout"
bash "$script" "$work/images.txt" "$work/cache" "$work/layout"
cmp "$work/first/c8s-0.tar" "$work/layout/c8s-0.tar"
# Layouts for digests no longer listed are pruned from the persisted cache.
mkdir -p "$work/cache/oci-stale/blobs"
bash "$script" "$work/images.txt" "$work/cache" "$work/pruned"
[[ ! -e "$work/cache/oci-stale" && -d "$cached" ]]

local_images="$work/local images"
mkdir -p "$local_images"
cp -a "$OCI_SOURCE" "$local_images/armtls-mesh"
digest=$(cut -d@ -f2 "$work/images.txt")
registry=ghcr.io/confidential-dot-ai
select_image_source "$registry/armtls-mesh:fixture" "$local_images" "$registry"
resolved=$("$REAL_ORAS" manifest fetch "${IMAGE_MANIFEST_ARGS[@]}" --descriptor "$IMAGE_SOURCE_REF" | jq -r .digest)
[[ "$resolved" == "$digest" ]]
select_image_source registry.example.com/core:fixture "$local_images" "$registry"
[[ "$IMAGE_SOURCE_REF" == registry.example.com/core:fixture && ${#IMAGE_MANIFEST_ARGS[@]} == 0 && ${#IMAGE_COPY_ARGS[@]} == 0 ]]

printf '%s\n' "$registry/armtls-mesh@$digest" > "$work/local.txt"
bash "$script" "$work/local.txt" "$work/local-cache" "$work/local-first" "$local_images"
bash "$script" "$work/local.txt" "$work/local-cache" "$work/local-second" "$local_images"
cmp "$work/local-first/c8s-0.tar" "$work/local-second/c8s-0.tar"
bash "$script" "$work/images.txt" "$work/cache" "$work/external" "$local_images"
cmp "$work/first/c8s-0.tar" "$work/external/c8s-0.tar"

python3 - "$work/first/c8s-0.tar" "$work/images.txt" "$work/local-first/c8s-0.tar" "$work/local.txt" <<'PYCHECK'
import hashlib, json, pathlib, sys, tarfile
for archive_path, refs_path in zip(sys.argv[1::2], sys.argv[2::2]):
    ref = pathlib.Path(refs_path).read_text().strip()
    with tarfile.open(archive_path) as archive:
        index = json.load(archive.extractfile("index.json"))
        assert len(index["manifests"]) == 1
        descriptor = index["manifests"][0]
        assert descriptor["digest"] == ref.split("@")[1]
        assert descriptor["annotations"]["io.containerd.image.name"] == ref
        for item in archive:
            assert item.uid == item.gid == item.mtime == 0
            if item.isfile() and item.name.startswith("blobs/sha256/"):
                assert hashlib.sha256(archive.extractfile(item).read()).hexdigest() == item.name.split("/")[-1]
        source_index = json.load(archive.extractfile("blobs/sha256/" + descriptor["digest"].split(":")[1]))
        assert {item["platform"]["architecture"] for item in source_index["manifests"]} == {"amd64", "arm64"}
PYCHECK

cp -a "$OCI_SOURCE" "$local_images/core"
bash "$script" "$work/images.txt" "$work/custom-cache" "$work/custom" "$local_images" registry.example.com
cmp "$work/first/c8s-0.tar" "$work/custom/c8s-0.tar"
if bash "$script" "$work/local.txt" "$work/local-cache" "$work/missing" "$work/absent" >"$work/missing.log" 2>&1; then
    echo "accepted a missing local image layout" >&2; exit 1
fi
grep -q 'local OCI layout missing' "$work/missing.log"
python3 - "$local_images/armtls-mesh/blobs/sha256/${digest#sha256:}" <<'PYCORRUPT'
import pathlib, sys
path = pathlib.Path(sys.argv[1])
path.write_bytes(path.read_bytes().replace(b'"amd64"', b'"amd65"'))
PYCORRUPT
if bash "$script" "$work/local.txt" "$work/corrupt-cache" "$work/corrupt" "$local_images"; then
    echo "accepted corrupt local image content" >&2; exit 1
fi
printf '%s\n' registry.example.com/core:latest > "$work/invalid.txt"
if bash "$script" "$work/invalid.txt" "$work/cache" "$work/invalid"; then
    echo "accepted an unpinned image" >&2; exit 1
fi
: > "$work/empty.txt"
if bash "$script" "$work/empty.txt" "$work/cache" "$work/empty"; then
    echo "accepted an empty core image set" >&2; exit 1
fi
echo "airgap images preserve measured pins and reproducible complete OCI content"
