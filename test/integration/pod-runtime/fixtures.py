#!/usr/bin/env python3
"""Build the offline test workload and validate its immutable runtime inputs."""
import hashlib
import io
import json
import re
import sys
import tarfile
import uuid
from pathlib import Path


def prepare(source, stage, architecture):
    pins = json.loads((Path(__file__).parent / "runtime-pins.json").read_text())
    sync = (source / "node-guest-image/c8s/mkosi.sync").read_text()
    versions = re.findall(r'^RKE2_VERSION="([^"]+)"$', sync, re.MULTILINE)
    if versions != [pins["rke2Version"]]:
        raise ValueError("runtime pin must be updated with the guest RKE2 version")
    if architecture not in pins["platforms"]:
        raise ValueError("runtime integration supports native Linux amd64 and arm64")
    policy = (source / "node-guest-image/c8s/image-policy.yaml.in").read_text()
    entries = re.findall(
        r'label: "(docker.io/rancher/rke2-runtime:[^"]+)"\s+'
        r'containers:\s+- digest: "(sha256:[a-f0-9]{64})"',
        policy,
    )
    expected_ref = "docker.io/rancher/rke2-runtime:" + versions[0].replace("+", "-")
    if entries != [(expected_ref, pins["airgapFloorDigest"])]:
        raise ValueError("runtime registry pin must be reviewed with the measured airgap floor")
    kind_lib = (source / "test/integration/cluster/lib.sh").read_text()
    runner = re.findall(r'NODE_IMAGE="\$\{C8S_IT_NODE_IMAGE:-([^}]+)\}"', kind_lib)
    if len(runner) != 1 or not re.fullmatch(
        r"kindest/node:[A-Za-z0-9.-]+@sha256:[a-f0-9]{64}", runner[0]
    ):
        raise ValueError("expected the existing digest-pinned kind runner image")
    for digest in [pins["registryIndex"], *pins["platforms"].values()]:
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
            raise ValueError("runtime inputs require sha256 pins")
    inputs = {
        "runId": str(uuid.uuid4()),
        "rke2Version": pins["rke2Version"],
        "runtimeImage": "docker.io/rancher/rke2-runtime@" + pins["platforms"][architecture],
        "runtimeRegistryIndex": pins["registryIndex"],
        "runtimePlatformDigest": pins["platforms"][architecture],
        "airgapFloorDigest": pins["airgapFloorDigest"],
        "runnerImage": runner[0],
        "architecture": architecture,
        "scope": "native snapshotter; simulated measurement register and credential broker",
        "runtimeProvenance": "digest-pinned registry release runtime; guest airgap byte equivalence unverified",
    }
    (stage / "inputs.json").write_text(json.dumps(inputs, indent=2) + "\n")
    (stage / "pins.json").write_bytes(
        (source / "internal/testdata/node-identities.json").read_bytes()
    )


def image(stage, architecture):
    blobs = {}

    def blob(data, media):
        digest = hashlib.sha256(data).hexdigest()
        blobs["blobs/sha256/" + digest] = data
        return {"mediaType": media, "digest": "sha256:" + digest, "size": len(data)}

    def obj(value, media):
        return blob(json.dumps(value, separators=(",", ":")).encode(), media)

    layer = io.BytesIO()
    with tarfile.open(fileobj=layer, mode="w") as archive:
        for name in ["pause", "marker-workload"]:
            data = (stage / "marker-workload").read_bytes()
            entry = tarfile.TarInfo(name)
            entry.size, entry.mode = len(data), 0o755
            archive.addfile(entry, io.BytesIO(data))
        entry = tarfile.TarInfo("tmp")
        entry.type, entry.mode = tarfile.DIRTYPE, 0o1777
        archive.addfile(entry)
    layer_desc = blob(layer.getvalue(), "application/vnd.oci.image.layer.v1.tar")
    config = obj(
        {
            "architecture": architecture,
            "os": "linux",
            "config": {"Entrypoint": ["/pause"], "Env": []},
            "rootfs": {"type": "layers", "diff_ids": [layer_desc["digest"]]},
        },
        "application/vnd.oci.image.config.v1+json",
    )
    manifest = obj(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": config,
            "layers": [layer_desc],
        },
        "application/vnd.oci.image.manifest.v1+json",
    )
    tag = "example.invalid/pod-start:fixture"
    descriptor = {
        **manifest,
        "annotations": {"org.opencontainers.image.ref.name": tag},
    }
    files = {
        "oci-layout": b'{"imageLayoutVersion":"1.0.0"}',
        "index.json": json.dumps({"schemaVersion": 2, "manifests": [descriptor]}).encode(),
        **blobs,
    }
    with tarfile.open(stage / "fixtures.tar", "w") as archive:
        for name, data in files.items():
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            archive.addfile(entry, io.BytesIO(data))
    fixture = {
        "tag": tag,
        "pin": manifest["digest"],
        "reference": "example.invalid/pod-start@" + manifest["digest"],
    }
    (stage / "fixture.json").write_text(json.dumps(fixture, indent=2) + "\n")


def receipt(inputs_path, result_path):
    inputs = json.loads(inputs_path.read_text())
    result = json.loads(result_path.read_text())
    modes = {"absent", "deny", "failed-extend", "late", "socket-lost", "disconnect", "replayed", "admit"}
    if result.get("runId") != inputs["runId"]:
        raise ValueError("runtime result is not from this invocation")
    if result.get("architecture") != inputs["architecture"]:
        raise ValueError("runtime result architecture does not match its inputs")
    if result.get("sandbox-started-without-workload-permission") is not True:
        raise ValueError("missing sandbox start assertion")
    cases = result.get("cases", {})
    if set(cases) != modes:
        raise ValueError("runtime receipt must contain all eight required cases")
    container_ids = set()
    for mode, case in cases.items():
        container_id = case.get("containerId")
        if not isinstance(container_id, str) or not container_id or container_id in container_ids:
            raise ValueError("each runtime case requires a distinct container identity")
        container_ids.add(container_id)
        if case.get("markerExecuted") is not (mode == "admit"):
            raise ValueError("runtime marker assertion failed: " + mode)
        if mode != "admit" and not case.get("refusal"):
            raise ValueError("missing runtime refusal: " + mode)
        if mode != "absent":
            request = case.get("nriRequest", {})
            if (request.get("containerId") != container_id
                    or not request.get("sandboxId")
                    or request.get("sandboxId") != result.get("sandboxId")
                    or type(request.get("pid")) is not int or request["pid"] <= 0):
                raise ValueError("invalid created NRI process identity: " + mode)
            consumed = case.get("consumedByWrapper")
            if mode == "admit":
                if consumed != [request] or case.get("taskPid") != request["pid"]:
                    raise ValueError("wrapper did not consume the exact created task once")
            elif consumed:
                raise ValueError("wrapper consumed a refused runtime permission: " + mode)
    print("PASS: fresh runtime receipt validates all eight cases and exact task identity")


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "prepare":
        prepare(Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4])
    elif len(sys.argv) == 4 and sys.argv[1] == "image":
        image(Path(sys.argv[2]), sys.argv[3])
    elif len(sys.argv) == 4 and sys.argv[1] == "receipt":
        receipt(Path(sys.argv[2]), Path(sys.argv[3]))
    else:
        raise SystemExit("usage: fixtures.py prepare SOURCE STAGE ARCH | image STAGE ARCH | receipt INPUTS RESULT")
