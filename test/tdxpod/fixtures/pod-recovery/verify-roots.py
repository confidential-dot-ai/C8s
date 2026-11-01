"""Compare actual immutable production bytes before publishing the fixture."""
import hashlib
import json
from pathlib import Path
import sys

old, new, work = map(Path, sys.argv[1:])
paths = ["usr/local/bin/c8s", "usr/local/bin/c8s-runc", "opt/nri/plugins/10-nri-image-policy",
         "usr/lib/c8s",
         "etc/systemd/system/podcvm-status.service", "etc/systemd/system/podcvm-kubelet.service",
         "etc/systemd/system/podcvm-containerd.service", "etc/systemd/system/rke2-role.service",
         "etc/attestation-api/config.toml", "usr/lib/confai/state.d/60-c8s.conf"]
hashes = {}
def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()
for item in paths:
    source = old / item
    if not source.exists() and not source.is_symlink():
        raise ValueError("baseline production path is missing: " + item)
    members = [source] if not source.is_dir() else sorted(source.rglob("*"))
    for path in members:
        relative = path.relative_to(old)
        target = new / relative
        if path.is_symlink():
            if not target.is_symlink() or path.readlink() != target.readlink():
                raise ValueError("production symlink changed: " + str(relative))
        elif path.is_file():
            if target.is_symlink() or not target.is_file() or path.stat().st_mode != target.stat().st_mode or digest(path) != digest(target):
                raise ValueError("production bytes changed: " + str(relative))
            hashes[str(relative)] = digest(path)
    if source.is_dir() and {p.relative_to(source) for p in source.rglob("*")} != {p.relative_to(new/item) for p in (new/item).rglob("*")}:
        raise ValueError("production runtime file list changed")
for forbidden in ["etc/systemd/system/serial-getty@ttyS0.service.d", "etc/ssh/sshd_config",
                  "var/lib/rancher/rke2/agent/etc/containerd/config-v3.toml.d/60-dev-runc.toml"]:
    if (new/forbidden).exists():
        raise ValueError("debug profile detected")
controller = "usr/local/libexec/pod-recovery-fixture"
if (old/controller).exists() or digest(new/controller) != digest(work/"pod-recovery/mkosi.extra"/controller):
    raise ValueError("test controller provenance differs")
receipt = {"baseline": "05211a8b106415a0aefd5f47bc40b266b0c1dacd", "files": hashes,
           "controllerSHA256": digest(new/controller)}
(work/"runtime-components.json").write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
