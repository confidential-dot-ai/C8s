#!/usr/bin/env python3
"""Build the offline test workload and validate its immutable runtime inputs."""
import hashlib
import io
import json
import re
import sys
import subprocess
import tarfile
import uuid
from pathlib import Path


def validate_runtime_inputs(source, pins, architecture):
    sync = (source / "images/node-guest/c8s/mkosi.sync").read_text()
    versions = re.findall(r'^RKE2_VERSION="([^"]+)"$', sync, re.MULTILINE)
    if versions != [pins["rke2Version"]]:
        raise ValueError("runtime pin must be updated with the guest RKE2 version")
    if architecture not in pins["platforms"]:
        raise ValueError("runtime integration supports native Linux amd64 and arm64")
    # The guest extracts runtime binaries from these pinned amd64 bundles.
    # rke2-runtime is unpacked, so it is not an executable floor entry.
    for bundle in ("core", "cilium"):
        checksums = re.findall(
            rf'^RKE2_IMAGES_{bundle.upper()}_SHA256="([a-f0-9]{{64}})"$',
            sync, re.MULTILINE,
        )
        if checksums != [pins["guestAirgapBundlesAMD64"][bundle]]:
            raise ValueError("runtime pins must be reviewed with the guest " + bundle + " bundle")
    policy = (source / "images/node-guest/c8s/image-policy.yaml.in").read_text()
    cni = pins["cni"]
    # Match the one current Cilium init rule, not a label or an arbitrary digest.
    cni_entries = re.findall(
        r'^      cilium:\n        initContainers:\n'
        r'          - digest: "(sha256:[a-f0-9]{64})"\n'
        r'            image: "(docker.io/rancher/hardened-cni-plugins:[^"]+)"$',
        policy, re.MULTILINE,
    )
    expected_cni = "docker.io/rancher/hardened-cni-plugins:" + cni["version"]
    cni_images = re.findall(
        r'^\s*image: "(docker.io/rancher/hardened-cni-plugins:[^"]+)"$',
        policy, re.MULTILINE,
    )
    if cni_entries != [(cni["airgapFloorDigest"], expected_cni)] or cni_images != [expected_cni]:
        raise ValueError("CNI registry pin must be reviewed with the measured Cilium init rule")
    kind_lib = (source / "test/integration/cluster/lib.sh").read_text()
    runner = re.findall(r'NODE_IMAGE="\$\{C8S_IT_NODE_IMAGE:-([^}]+)\}"', kind_lib)
    if len(runner) != 1 or not re.fullmatch(
        r"kindest/node:[A-Za-z0-9.-]+@sha256:[a-f0-9]{64}", runner[0]
    ):
        raise ValueError("expected the existing digest-pinned kind runner image")
    for digest in [pins["registryIndex"], *pins["platforms"].values(), pins["historicalRuntimeAirgapDigest"], cni["registryIndex"], *cni["platforms"].values(), cni["airgapFloorDigest"]]:
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
            raise ValueError("runtime inputs require sha256 pins")
    return runner[0]


def prepare(source, stage, architecture):
    pins = json.loads((Path(__file__).parent / "runtime-pins.json").read_text())
    runner = validate_runtime_inputs(source, pins, architecture)
    cni = pins["cni"]
    inputs = {
        "runId": str(uuid.uuid4()),
        "sourceRevision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, timeout=10).decode().strip(),
        "sourceDiffSHA256": hashlib.sha256(subprocess.check_output(["git", "diff", "HEAD", "--binary"], cwd=source, timeout=10)).hexdigest(),
        "kubeletTestSHA256": hashlib.sha256((source / "internal/cmds/nri-image-policy/pod_runtime_kubelet_integration_linux_test.go").read_bytes()).hexdigest(),
        "recoveryTestSHA256": hashlib.sha256((source / "internal/cmds/nri-image-policy/pod_runtime_recovery_integration_linux_test.go").read_bytes()).hexdigest(),
        "rke2Version": pins["rke2Version"],
        "runtimeImage": "docker.io/rancher/rke2-runtime@" + pins["platforms"][architecture],
        "cniImage": "docker.io/rancher/hardened-cni-plugins@" + cni["platforms"][architecture],
        "cniRegistryIndex": cni["registryIndex"],
        "cniAirgapFloorDigest": cni["airgapFloorDigest"],
        "runtimeRegistryIndex": pins["registryIndex"],
        "runtimePlatformDigest": pins["platforms"][architecture],
        "historicalRuntimeAirgapDigest": pins["historicalRuntimeAirgapDigest"],
        "guestAirgapBundlesAMD64": pins["guestAirgapBundlesAMD64"],
        "runnerImage": runner,
        "architecture": architecture,
        "scope": "native snapshotter; simulated measurement register and credential broker",
        "runtimeProvenance": "digest-pinned registry release runtime; runtime/CNI guest airgap byte equivalence unverified",
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
    descriptors = []
    for name in ["pod-start", "pod-recovery-mesh"]:
        config = obj(
            {
                "architecture": architecture,
                "os": "linux",
                "config": {"Entrypoint": ["/pause"], "Env": [], "Labels": {"fixture": name}},
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
        tag = "example.invalid/" + name + ":fixture"
        descriptors.append({**manifest, "annotations": {"org.opencontainers.image.ref.name": tag}})
        fixture = {"tag": tag, "pin": manifest["digest"], "reference": "example.invalid/" + name + "@" + manifest["digest"]}
        output = "fixture.json" if name == "pod-start" else "mesh-fixture.json"
        (stage / output).write_text(json.dumps(fixture, indent=2) + "\n")
    files = {
        "oci-layout": b'{"imageLayoutVersion":"1.0.0"}',
        "index.json": json.dumps({"schemaVersion": 2, "manifests": descriptors}).encode(),
        **blobs,
    }
    with tarfile.open(stage / "fixtures.tar", "w") as archive:
        for name, data in files.items():
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            archive.addfile(entry, io.BytesIO(data))



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


def recovery_receipt(inputs_path, result_path):
    inputs = json.loads(inputs_path.read_text())
    result = json.loads(result_path.read_text())
    if result.get("runId") != inputs["runId"]:
        raise ValueError("recovery result is not from this invocation")
    for key in ["fullClaimsPreserved", "taskPreserved", "oldGrantRefused", "cgroupIdentityChecked", "sandboxCleanup"]:
        if result.get(key) is not True:
            raise ValueError("missing production recovery assertion: " + key)
    for key in ["pluginProcessIds", "containerdProcessIds"]:
        pids = result.get(key)
        if not isinstance(pids, list) or len(pids) != 2 or len(set(pids)) != 2 or any(type(pid) is not int or pid <= 0 for pid in pids):
            raise ValueError("recovery did not replace the real processes: " + key)
    ids = [result.get(key) for key in ["meshContainerId", "appContainerId", "removedContainerId", "postRecoveryContainerId"]]
    if any(not isinstance(value, str) or not value for value in ids) or len(set(ids)) != 4:
        raise ValueError("recovery requires four distinct actual runtime container identities")
    if result.get("historicalObservations") != 3 or len(result.get("measuredDigests", [])) != 2:
        raise ValueError("recovery did not preserve distinct removed same-image history")
    if result.get("negative") != {"missing-history": True, "tampered-history": True, "pending-transition": True}:
        raise ValueError("recovery must refuse each invalid retained-history state")
    if not re.fullmatch(r"pcvm-[a-f0-9]{64}", result.get("credentialInstanceId", "")):
        raise ValueError("missing stable recovery credential identity")
    if not re.fullmatch(r"[a-f0-9]{64}", result.get("assignedPolicySHA256", "")):
        raise ValueError("missing unchanged assigned-policy identity")
    if type(result.get("taskPid")) is not int or result["taskPid"] <= 0 or not result.get("sandboxId"):
        raise ValueError("missing retained actual task identity")
    print("PASS: fresh production recovery receipt validates actual process restart, full history and fail-closed state")


def kubelet_receipt(inputs_path, result_path):
    inputs = json.loads(inputs_path.read_text())
    result = json.loads(result_path.read_text())
    if result.get("runId") != inputs["runId"]:
        raise ValueError("kubelet recovery result is not from this invocation")
    for key in ["assignmentPreserved", "fullClaimsPreserved", "tasksPreserved", "kubeletReportedRunning", "sandboxCleanup"]:
        if result.get(key) is not True:
            raise ValueError("missing actual kubelet recovery assertion: " + key)
    for key in ["kubeletProcessIds", "pluginProcessIds", "containerdProcessIds"]:
        pids = result.get(key)
        if not isinstance(pids, list) or len(pids) != 2 or len(set(pids)) != 2 or any(type(pid) is not int or pid <= 0 for pid in pids):
            raise ValueError("kubelet recovery did not replace the actual service process: " + key)
    if not re.fullmatch(r"pcvm-[a-f0-9]{64}", result.get("credentialInstanceId", "")) or not result.get("runtimePodUID"):
        raise ValueError("kubelet recovery lost credential or runtime Pod identity")
    for key in ["appPID", "meshPID"]:
        if type(result.get(key)) is not int or result[key] <= 0:
            raise ValueError("kubelet recovery is missing its retained task PID")
    if not result.get("appContainerId") or not result.get("meshContainerId") or result["appContainerId"] == result["meshContainerId"]:
        raise ValueError("kubelet recovery is missing distinct task identities")
    print("PASS: fresh kubelet receipt validates actual static Pod service restart and retained tasks")


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "prepare":
        prepare(Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4])
    elif len(sys.argv) == 4 and sys.argv[1] == "image":
        image(Path(sys.argv[2]), sys.argv[3])
    elif len(sys.argv) == 4 and sys.argv[1] == "receipt":
        receipt(Path(sys.argv[2]), Path(sys.argv[3]))
    elif len(sys.argv) == 4 and sys.argv[1] == "recovery-receipt":
        recovery_receipt(Path(sys.argv[2]), Path(sys.argv[3]))
    elif len(sys.argv) == 4 and sys.argv[1] == "kubelet-receipt":
        kubelet_receipt(Path(sys.argv[2]), Path(sys.argv[3]))
    else:
        raise SystemExit("usage: fixtures.py prepare SOURCE STAGE ARCH | image STAGE ARCH | receipt INPUTS RESULT | recovery-receipt INPUTS RESULT | kubelet-receipt INPUTS RESULT")
