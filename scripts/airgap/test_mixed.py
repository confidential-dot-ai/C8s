"""Exercise candidate staging. The GPU report is synthetic and cannot qualify hardware."""

import base64
import hashlib
import json
import os
import runpy
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

prepare = runpy.run_path(str(Path(__file__).with_name("prepare-mixed")))


def write(path: Path, data: bytes) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def encoded(data: Any) -> bytes:
    return json.dumps(data).encode()


def gpu(root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    rim = b'{"id":"driver/fixture","rim":"dGVzdA=="}\n'
    digest = hashlib.sha256(rim).hexdigest()
    write(root / "rims" / digest, rim)
    inputs = root / "responses/gpu"
    status = write(inputs / "ocsp.der", b"placeholder")
    for name in ("cert.pem", "issuer.pem"):
        write(inputs / name, b"placeholder")
    fingerprints = {"gpu": "f" * 64}
    policy = write(root / "run/policy.rego", b"fixture policy")
    ueids = [f"test-{i}" for i in range(8)]
    approval = {
        "target": "fixture",
        "rimResponses": {"driver/fixture": digest},
        "rimSha256": [digest],
        "certificateFingerprints": fingerprints,
        "policySha256": policy,
        "ueids": ueids,
        "maxStatusAgeSeconds": 90,
    }
    pin = write(root / "run/approval.json", encoded(approval))
    claim = {
        "x-nvidia-gpu-" + chain + "-cert-chain": {
            "x-nvidia-cert-expiration-date": "2026-10-16T00:30:00Z"
        }
        for chain in ("attestation-report", "vbios-rim", "driver-rim")
    }
    verdict = write(
        root / "run/attest.json",
        encoded({"claims": [claim | {"ueid": u} for u in ueids]}),
    )
    return approval, approval | {
        "approvalSha256": pin,
        "gpuVerdictSha256": verdict,
        "ocspSha256": {"gpu": status},
        "earliestExpiryUtc": "2026-10-16T00:45:00Z",
        "limitingObject": "gpu",
        "observedRefreshSeconds": 60,
        "remainingSeconds": 2000,
        "refreshStartedUnix": 1,
        "importFinishedUnix": 61,
    }


def test_nvidia_selectors(tmp_path: Path) -> None:
    store = tmp_path / "objects"
    store.mkdir()
    approval, report = gpu(tmp_path)

    def stage(enrollment: dict[str, Any], verified: dict[str, Any]) -> dict[str, Any]:
        manifest: dict[str, Any] = {"target": "fixture", "objects": {}}
        prepare["stage_nvidia"](tmp_path, store, manifest, enrollment, verified)
        return dict(manifest["objects"])

    objects = stage(approval, report)
    assert set(objects) == {
        "nvidia/ocsp/" + "f" * 64,
        "nvidia/rim/driver/fixture",
        "nvidia/policy",
    }
    digest = objects["nvidia/rim/driver/fixture"]["sha256"]
    assert (store / digest).read_bytes() == (tmp_path / "rims" / digest).read_bytes()
    change: dict[str, Any]
    for change in (
        {"target": "other"},
        {"rimResponses": {"other": digest}},
        {"rimResponses": {"../x": digest}},
        {"certificateFingerprints": {}},
        {"policySha256": "0" * 64},
    ):
        with pytest.raises(ValueError):
            stage(approval | change, report)
    with pytest.raises(ValueError):
        stage(approval, report | {"rimSha256": []})
    (tmp_path / "responses/gpu/ocsp.der").unlink()
    os.mkfifo(tmp_path / "responses/gpu/ocsp.der")
    with pytest.raises(ValueError, match="non-regular file"):
        stage(approval, report)
    (tmp_path / "responses/gpu/ocsp.der").unlink()
    write(tmp_path / "responses/gpu/ocsp.der", b"changed")
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        stage(approval, report)


def test_prepare_with_signed_intel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    location = os.getenv("C8S_INTEL_CORPUS")
    if not location:
        pytest.skip("requires C8S_INTEL_CORPUS and the check-intel CLI")
    corpus = Path(location)
    state, intel, source, out = [
        tmp_path / x for x in ("state", "intel", "gpu", "candidate")
    ]
    write(state / "enrolled-quote.bin", (corpus / "quote.bin").read_bytes())
    clock = state / "site-time"
    write(clock, b"#!/bin/sh\necho 2026-10-16T00:00:00Z\n")
    clock.chmod(0o700)
    # Fix only the test workstation clock to the signed Intel corpus date.
    write(
        tmp_path / "sitecustomize.py",
        b"import os,time\ntime.time=lambda:float(os.environ['TEST_UTC'])\n",
    )
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    monkeypatch.setenv("TEST_UTC", "1792108800")
    key = state / "signing-key"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ED25519", "-out", key], check=True
    )
    pub = subprocess.check_output(["openssl", "pkey", "-in", key, "-pubout"], text=True)
    write(state / "profile.json", encoded({"mediaPublicKey": pub, "target": "fixture"}))
    store = intel / "objects"
    objects = {}
    for url, response in json.loads((corpus / "pcs.json").read_bytes()).items():
        data = base64.b64decode(response["body"])
        digest = write(store / hashlib.sha256(data).hexdigest(), data)
        objects[url] = {"sha256": digest, "header": response.get("header")}
    manifest = {
        "generation": 2,
        "target": "fixture",
        "expiresAt": "2026-10-16T01:00:00Z",
        "objects": objects,
    }
    prepare["sign"](intel, manifest, state, key)
    _, report = gpu(source)
    program = tmp_path / "repo/scripts/airgap/prepare-mixed"
    program.parent.mkdir(parents=True)
    shutil.copy2(Path(__file__).with_name("prepare-mixed"), program)
    checker = tmp_path / "repo/test/e2e/b200/refresh-window.py"
    write(checker, b'#!/bin/sh\ncat "$1/../report.json"\n')
    checker.chmod(0o700)
    write(source / "report.json", encoded(report | {"remainingSeconds": 1900}))
    qualification = write(source / "refresh-report.json", encoded(report))
    pins = [report["approvalSha256"], qualification]
    cmd = [program, intel, state, source, *pins, "1", "61", "3", key, out]
    assert b"earliest expiry 2026-10-16T00:30:00Z" in subprocess.check_output(cmd)
    selection = json.loads((out / "active").read_bytes())
    snapshot = out / "snapshots" / (selection["sha256"] + ".json")
    mixed = json.loads(snapshot.read_bytes())
    assert mixed["generation"] == selection["generation"] == 3
    assert len(mixed["objects"]) == 7 and mixed["expiresAt"] == "2026-10-16T00:30:00Z"
    assert all(mixed["objects"][url] == ref for url, ref in objects.items())
    sig = snapshot.with_suffix(".sig")
    cli = ["c8s", "collateral", "check-intel", state / "enrolled-quote.bin"]
    check = [*cli, state / "profile.json", snapshot, sig, out / "objects"]
    result = subprocess.run(
        check, input=b"2026-10-16T00:00:00Z", capture_output=True, check=False
    )
    assert result.returncode and b"four Intel objects" in result.stderr
    assert subprocess.run(cmd, check=False, capture_output=True).returncode
    rejected = tmp_path / "rejected"
    cmd[-1] = rejected

    def rejected_with(message: bytes) -> None:
        result = subprocess.run(cmd, check=False, capture_output=True)
        assert result.returncode and message in result.stderr and not rejected.exists()

    cmd[1] = out
    rejected_with(b"four Intel records")
    cmd[1] = intel
    cmd[-3] = "2"
    rejected_with(b"reserve a new")
    cmd[-3] = "3"
    write(clock, b"#!/bin/sh\necho 2026-10-16T00:29:00Z\n")
    rejected_with(b"site time disagrees")
    monkeypatch.setenv("TEST_UTC", "1792110540")
    rejected_with(b"media turnaround")
    write(source / "report.json", encoded(report | {"refreshStartedUnix": 2}))
    rejected_with(b"report differs")
    write(source / "report.json", encoded(report))
    clock.unlink()
    assert subprocess.run(cmd, check=False, capture_output=True).returncode
    assert not rejected.exists()
