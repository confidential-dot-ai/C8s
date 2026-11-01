"""Capture fixture pins only after verified disk comparison and both pushes."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

work, variant, run, overlay = Path(sys.argv[1]), *sys.argv[2:]
if not re.fullmatch(r"[0-9a-f]{40}", overlay) or variant != "rke2-tdx-recovery-" + overlay[:12] or not re.fullmatch(r"[1-9][0-9]*", run):
    raise ValueError("invalid isolated fixture publication identity")
repository = "ghcr.io/confidential-dot-ai/node-guest-base"
def command(*args):
    return subprocess.check_output(args, timeout=120)
def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
refs = {}
for field, suffix in [("image", "-cdi-05211a8"), ("artifact", "-05211a8")]:
    descriptor = json.loads(command("oras", "manifest", "fetch", "--descriptor", repository + ":" + variant + suffix))
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", descriptor["digest"]):
        raise ValueError("invalid immutable descriptor")
    refs[field] = repository + "@" + descriptor["digest"]
artifact = json.loads(command("oras", "manifest", "fetch", refs["artifact"]))
layers = artifact["layers"]
def layer(name):
    matches = [x for x in layers if x.get("annotations", {}).get("org.opencontainers.image.title") == name]
    if len(matches) != 1:
        raise ValueError("ambiguous published layer: " + name)
    return matches[0]["digest"]
manifest_hash = digest(work/"manifest.json")
manifest = json.loads((work/"manifest.json").read_bytes())
disk = manifest["outputs"]["disk_image"]["sha256"]
if layer("manifest.json") != "sha256:" + manifest_hash or layer("disk.raw") != "sha256:" + disk:
    raise ValueError("published fixture differs from the verified build")
components = json.loads((work/"runtime-components.json").read_text())
receipt = {"schema": 1, "source": components["baseline"], "profileSource": components["baseline"],
           "buildRun": run, **refs, "manifestSHA256": manifest_hash, "diskSHA256": disk,
           "meshImage": "ghcr.io/confidential-dot-ai/armtls-mesh@sha256:e05ccc28f168972c86ccc1bdb899a371264a38a0ef69a2f0eece6d9813baee27",
           "recoveryFixture": True, "overlaySource": overlay, "controllerSHA256": components["controllerSHA256"],
           "baselineDiskSHA256": "eb2dffb9712048ad23a2a62c04441c85f708cad60a846ce8cf4c5d7f4b610bb6",
           "runtimeComponentsSHA256": digest(work/"runtime-components.json")}
(work/"image.json").write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
print("Fixture receipt SHA256:", digest(work/"image.json"))
