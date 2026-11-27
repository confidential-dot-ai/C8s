#!/usr/bin/env python3
"""Install the site's approved role-specific attestation service before mkosi measures the guest."""

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any


def verify_config(conf: dict[str, Any], bind: str) -> None:
    if set(conf) - {"server", "auth", "nras", "token", "attestation", "verify"}:
        raise ValueError("unknown attestation service configuration section")
    if conf.get("server", {}).get("bind") != bind:
        raise ValueError(f"expected server.bind = {bind}")
    if conf["attestation"]["tdx_quote_method"] != "configfs" or conf["attestation"]["platforms"] != ["tdx"]:
        raise ValueError("the site service must quote TDX through configfs for the Unix QGS socket")
    verify = conf.get("verify", {})
    selected = {"helper": "/usr/local/bin/c8s", "profile": "/etc/c8s-site/profile.json"}
    if verify.get("selected_tdx") != selected or verify.get("warm") != []:
        raise ValueError("verify requires the measured selected_tdx helper and profile, and warm = []")


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def expected_digests(approval: Path) -> dict[str, str]:
    hashes = json.loads(approval.read_bytes())
    if not isinstance(hashes, dict) or set(hashes) != {"ta", "worker", "c8s"} or not all(
        isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) for value in hashes.values()
    ):
        raise ValueError("expected approved c8s, ta and worker executable SHA-256 digests")
    return hashes


def finalize(root: Path, profile: Path) -> None:
    ta = (root / "etc/systemd/system/ta.service").is_file()
    worker = (root / "usr/lib/c8s/worker-image").is_file()
    if ta == worker:
        raise ValueError("the measured image must contain exactly one of the TA and worker profiles")
    role = "ta" if ta else "worker"
    hashes = expected_digests(profile / "approved-verifiers.json")
    binaries = root / "usr/local/bin"
    if digest(binaries / "attestation-api") == hashes[role]:
        raise ValueError(f"the {role} candidate matches the pinned connected verifier")
    config = tomllib.loads((root / "etc/attestation-api/config.toml").read_text())
    verify_config(config, "127.0.0.1:8400")
    for key, name in ((role, "attestation-api"), ("c8s", "c8s")):
        candidate = profile / "verifiers" / key
        installed = binaries / name
        if digest(candidate) != hashes[key]:
            raise ValueError(f"{key} verifier differs from the site-approved SHA-256")
        shutil.copyfile(candidate, installed)
        installed.chmod(0o755)
        if digest(installed) != hashes[key]:
            raise ValueError(f"final {name} executable differs from the site-approved SHA-256")
    check = subprocess.run(["chroot", root, "/usr/local/bin/c8s", "collateral", "selected-tdx", "--help"],
                           capture_output=True, timeout=15, check=False)
    if check.returncode or b"c8s collateral selected-tdx PROFILE" not in check.stdout:
        detail = check.stderr.decode(errors="replace").strip() or "unexpected CLI usage"
        raise ValueError(f"the measured c8s helper failed its in-guest collateral selected-tdx PROFILE probe: {detail}")

    if worker:
        unit = root / "etc/systemd/system/gpu-cc-enforce.service.d/90-enrollment.conf"
        unit.parent.mkdir(parents=True, exist_ok=True)
        unit.write_text("[Service]\nEnvironment=GPU_CC_ENROLLMENT=/etc/c8s-site/gpu-ueids.json\n")


if __name__ == "__main__":
    try:
        finalize(Path(os.environ["BUILDROOT"]), Path(os.environ["SRCDIR"]) / "mkosi.profiles/site-offline")
    except (ValueError, KeyError, OSError, subprocess.TimeoutExpired) as err:
        sys.exit(str(err))
