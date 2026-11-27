"""Selection durability checks on a trusted workstation with a stand-in vendor verifier."""

import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

IMPORT = Path(__file__).with_name("import-intel")
ACTIVE = Path(__file__).with_name("active.cgi")


def stage(media: Path, generation: int) -> tuple[dict[str, Any], Path]:
    objects = {}
    for name in ["TCB", "QE", "PCK", "root"]:
        raw = (name + str(generation)).encode()
        pin = hashlib.sha256(raw).hexdigest()
        (media / "objects" / pin).write_bytes(raw)
        objects[name] = {"sha256": pin}
    m = {
        "generation": generation,
        "target": "test",
        "expiresAt": "2030-01-02T00:00:00Z",
        "objects": objects,
    }
    raw = json.dumps(m).encode()
    pin = hashlib.sha256(raw).hexdigest()
    (media / "snapshots" / f"{pin}.json").write_bytes(raw)
    (media / "snapshots" / f"{pin}.sig").write_bytes(b"s" * 64)
    selection = {"generation": generation, "sha256": pin}
    (media / "active").write_text(json.dumps(selection))
    return selection, media / "objects" / objects["QE"]["sha256"]


def test_refresh(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state, media, store = [tmp_path / name for name in ["state", "media", "served"]]
    state.mkdir()
    for root in [media, store]:
        (root / "objects").mkdir(parents=True)
        (root / "snapshots").mkdir()
    (state / "profile.json").write_text('{"target":"test"}')
    clock = state / "site-time"
    clock.write_text("#!/bin/sh\necho 2029-01-01T00:00:00Z\n")
    clock.chmod(0o755)
    verifier = tmp_path / "c8s"
    verifier.write_text(
        '#!/bin/sh\nread -r clock || test -n "$clock"\ntest "$clock" = \'2029-01-01T00:00:00+00:00\'\n'
    )
    verifier.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tmp_path}:{os.environ['PATH']}")
    monkeypatch.setenv("C8S_SITE_STATE", str(state))
    monkeypatch.setenv("REQUEST_METHOD", "GET")
    challenge = "a" * 64
    monkeypatch.setenv("HTTP_X_C8S_CHALLENGE", challenge)

    def run_import() -> int:
        return subprocess.run([IMPORT, media, state, store], check=False).returncode

    a, _ = stage(media, 1)
    assert run_import() == 0
    b, obj = stage(media, 2)
    obj.write_bytes(b"changed")
    assert run_import() != 0
    assert json.loads((state / "active").read_bytes()) == a
    stage(media, 2)
    assert run_import() == 0
    stage(media, 1)
    assert run_import() != 0
    assert json.loads((state / "active").read_bytes()) == b
    opt = subprocess.check_output([ACTIVE]).decode()
    assert challenge in opt and b["sha256"] in opt
    stage(media, 3)
    verifier.write_text("#!/bin/sh\nexit 1\n")
    assert run_import() != 0
    clock.unlink()
    assert b"503 Service Unavailable" in subprocess.check_output([ACTIVE])
    assert json.loads((state / "active").read_bytes()) == b
