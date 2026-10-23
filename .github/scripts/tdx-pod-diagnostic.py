#!/usr/bin/env python3
"""Manual, disposable boot diagnostics for build 39943645155; never acceptance."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.request
import uuid

# Historical build: matching CLI/components, but a node-only profile from main.
SOURCE = "4774df9ebc1bd186765b8997f5356005510b9342"
PROFILE_SOURCE = "00f43aca8047bd5e2a3e30586d6a72b3091e5da5"
IMAGE = "ghcr.io/confidential-dot-ai/node-guest-base@sha256:94609d81bb2309ef0e73319551dcc46a2ddbf217c7a34cb413586898b5116b52"
MANIFEST = "f9b69ce2ad039fb36c6b16bb805befa453b4df6b0706915af8411edfcaf22bc1"
DISK = "bc3bcd04d700370edaed13899370e783361aa0a6368449426fecbbd182b9d49d"
PAUSE = "docker.io/rancher/mirrored-pause:3.10.2@sha256:f548e0e8e3dc1896ca956272154dde3314e8cc4fde0a57577ee9fa1c63f5baf4"
NS = "confai-images"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def budget(deadline):
    remaining = 30 if deadline is None else deadline - time.monotonic()
    require(remaining > 0, "diagnostic phase deadline reached")
    return min(30, remaining)


def pause(deadline, seconds):
    time.sleep(min(seconds, max(0, deadline - time.monotonic())))


def write(path, value):
    data = value if isinstance(value, bytes) else (json.dumps(value, indent=2) + "\n").encode()
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def command(argv, data=None, timeout=30):
    result = subprocess.run(argv, input=data, capture_output=True, timeout=timeout)
    require(result.returncode == 0, "command failed: " + result.stderr[-1200:].decode(errors="replace"))
    return result.stdout


def kube(*args, data=None, timeout=30, raw=False):
    # A request-timeout flag disables kubectl's in-cluster fallback in this lane.
    body = command(["kubectl", "-n", NS, *args], data=data, timeout=timeout)
    return body if raw else json.loads(body) if body.strip() else None


def validate_manifest(data):
    require(len(data) <= 65536 and hashlib.sha256(data).hexdigest() == MANIFEST, "diagnostic manifest digest differs")
    manifest = json.loads(data)
    require(manifest["inputs"]["base_image"]["sha256"] == DISK, "diagnostic disk digest differs")
    require(all(re.fullmatch(r"[0-9a-f]{96}", manifest["tdx"][k]) for k in ("mrtd", "rtmr1", "rtmr2")), "incomplete TDX identity")
    return manifest


class Diagnostic:
    def __init__(self, root, run, attempt, repo):
        require(re.fullmatch(r"[1-9][0-9]*", run) and re.fullmatch(r"[1-9][0-9]*", attempt), "invalid workflow identity")
        require(repo.lower() == "confidential-dot-ai/c8s", "unexpected repository")
        self.root, self.run, self.attempt, self.repo = root, run, attempt, repo
        self.name = f"c8s-poddiag-{run}-{attempt}"
        self.private, self.evidence = root / "private", root / "evidence"
        self.private.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.evidence.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.ledger = self.private / "resources.json"
        self.nonce_file = self.private / "creation-nonces.json"

    def metadata(self, suffix):
        nonces = json.loads(self.nonce_file.read_text()) if self.nonce_file.exists() else {}
        if suffix not in nonces:
            require(not any(e["suffix"] == suffix for e in self.resources()), "owned resource lost its creation nonce")
            nonces[suffix] = uuid.uuid4().hex
            write(self.nonce_file, nonces)
        return {"name": self.name + suffix, "namespace": NS,
                "labels": {"ci.confidential.ai/managed": "true", "ci.confidential.ai/resource": "pod-diagnostic",
                           "ci.confidential.ai/run-id": self.run, "ci.confidential.ai/run-attempt": self.attempt},
                "annotations": {"ci.confidential.ai/repo": self.repo, "ci.confidential.ai/creation-nonce": nonces[suffix]}}

    def owned(self, obj, suffix, uid=None):
        expected, actual = self.metadata(suffix), obj["metadata"]
        require(all(actual.get(k) == expected[k] for k in ("name", "namespace")), "resource name or namespace differs")
        for field in ("labels", "annotations"):
            require(all(actual.get(field, {}).get(k) == v for k, v in expected[field].items()), "resource ownership differs")
        require(uid is None or actual["uid"] == uid, "resource UID changed")
        return obj

    def resources(self):
        return json.loads(self.ledger.read_text()) if self.ledger.exists() else []

    def create(self, kind, suffix, spec):
        require(kube("get", kind, self.name + suffix, "--ignore-not-found", "-o", "json") is None, "refusing existing resource")
        entries = self.resources()
        entry = {"kind": kind, "suffix": suffix, "uid": None}
        entries.append(entry)
        # Record intent before a request whose result could be lost.
        write(self.ledger, entries)
        obj = kube("create", "-f", "-", "-o", "json", data=json.dumps(spec).encode())
        self.owned(obj, suffix)
        entry["uid"] = obj["metadata"]["uid"]
        write(self.ledger, entries)
        return obj

    def get(self, kind, suffix, deadline=None):
        entry = next(e for e in self.resources() if e["kind"] == kind and e["suffix"] == suffix)
        obj = kube("get", kind, self.name + suffix, "-o", "json", timeout=budget(deadline))
        return self.owned(obj, suffix, entry["uid"])

    def prepare(self):
        url = "https://ghcr.io/token?service=ghcr.io&scope=repository:confidential-dot-ai/node-guest-base:pull"
        headers = {}
        token = os.environ.get("GH_TOKEN")
        if token:
            credentials = base64.b64encode((os.environ["GITHUB_ACTOR"] + ":" + token).encode()).decode()
            headers["Authorization"] = "Basic " + credentials
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30) as response:
            bearer = json.load(response)["token"]
        req = urllib.request.Request("https://ghcr.io/v2/confidential-dot-ai/node-guest-base/blobs/sha256:" + MANIFEST,
                                     headers={"Authorization": "Bearer " + bearer})
        with urllib.request.urlopen(req, timeout=60) as response:
            data = response.read(65537)
        validate_manifest(data)
        write(self.evidence / "manifest.json", data)
        cli = self.private / "c8s"
        version = command(["go", "version", "-m", str(cli)]).decode()
        require("vcs.revision=" + SOURCE in version and "vcs.modified=false" in version, "CLI does not match the clean diagnostic source")
        fixture = json.loads(Path(__file__).with_name("fixtures").joinpath("pod-diagnostic-4774.json").read_text())
        for name in ("pod", "workloads"):
            write(self.private / (name + ".json"), fixture[name])
        common = [str(cli), "node", "launch-config"]
        command(common + ["new", "--out", str(self.private / "server"), "--cluster-id", self.name,
                          "--image-manifest", str(self.evidence / "manifest.json")])
        command(common + ["new-pod", "--out", str(self.private / "bundle"), "--cluster-id", self.name,
                          "--image-manifest", str(self.evidence / "manifest.json"),
                          "--pod-manifest", str(self.private / "pod.json"), "--workloads", str(self.private / "workloads.json"),
                          "--server-address", "10.255.255.1", "--server-public-key", str(self.private / "server/server/pubkey")])
        write(self.evidence / "identity.json", {"componentSource": SOURCE, "profileSource": PROFILE_SOURCE, "buildRun": "39943645155", "image": IMAGE,
              "manifestSHA256": MANIFEST, "diskSHA256": DISK, "scope": "boot diagnostics only; CDS deliberately unavailable"})
        try:
            probe = subprocess.run(["kubectl", "-n", NS, "auth", "can-i", "create", "services"], capture_output=True, timeout=10)
            write(self.evidence / "service-authority.json", {"namespace": NS, "verb": "create", "resource": "services",
                  "allowed": probe.returncode == 0 and probe.stdout.strip() == b"yes", "exitCode": probe.returncode})
        except subprocess.TimeoutExpired:
            write(self.evidence / "service-authority.json", {"namespace": NS, "observation": "timed out"})

    def provision(self):
        root = {"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": self.metadata("-root"),
                "spec": {"accessModes": ["ReadWriteOnce"], "storageClassName": "local-path", "resources": {"requests": {"storage": "80Gi"}}}}
        self.create("pvc", "-root", root)
        binder = {"apiVersion": "v1", "kind": "Pod", "metadata": self.metadata("-binder"), "spec": {
            "restartPolicy": "Never", "activeDeadlineSeconds": 1500, "automountServiceAccountToken": False,
            "nodeSelector": {"kubevirt.io/tdx": "true"},
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{"name": "pause", "image": PAUSE, "resources": {"requests": {"cpu": "2", "memory": "8Gi"}, "limits": {"cpu": "2", "memory": "8Gi"}},
                "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}}}],
            "volumes": [{"name": "root", "persistentVolumeClaim": {"claimName": self.name + "-root", "readOnly": True}}]}}
        self.create("pod", "-binder", binder)
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            pvc, pod = self.get("pvc", "-root", deadline), self.get("pod", "-binder", deadline)
            node = pod.get("spec", {}).get("nodeName")
            if node and pvc.get("status", {}).get("phase") == "Bound":
                require(pvc["metadata"]["annotations"]["volume.kubernetes.io/selected-node"] == node, "root selected another node")
                break
            pause(deadline, 5)
        else:
            raise RuntimeError("TDX import binder did not schedule")
        kube("annotate", "pvc", self.name + "-root", "--resource-version=" + pvc["metadata"]["resourceVersion"],
             "cdi.kubevirt.io/storage.import.source=registry", "cdi.kubevirt.io/storage.import.endpoint=docker://" + IMAGE,
             "cdi.kubevirt.io/storage.contentType=kubevirt", "cdi.kubevirt.io/storage.import.secretName=ghcr-pull", raw=True)
        self.remove("pod", "-binder")
        deadline = time.monotonic() + 1200
        while time.monotonic() < deadline:
            pvc = self.get("pvc", "-root", deadline)
            phase = pvc["metadata"].get("annotations", {}).get("cdi.kubevirt.io/storage.pod.phase")
            require(phase != "Failed", "diagnostic CDI import failed")
            if phase == "Succeeded":
                break
            pause(deadline, 10)
        else:
            raise RuntimeError("diagnostic CDI import timed out")
        bundle = self.private / "bundle/pod"
        self.create("secret", "-opkey", {"apiVersion": "v1", "kind": "Secret", "metadata": self.metadata("-opkey"),
                    "type": "Opaque", "data": {name: base64.b64encode((bundle/name).read_bytes()).decode() for name in ("pubkey", "launch.yaml", "launch.yaml.sig")}})
        self.create("vm", "", self.vm())

    def vm(self):
        return {"apiVersion": "kubevirt.io/v1", "kind": "VirtualMachine", "metadata": self.metadata(""), "spec": {
            "runStrategy": "Once", "template": {"metadata": {"labels": {"kubevirt.io/domain": self.name}}, "spec": {
                "nodeSelector": {"kubevirt.io/tdx": "true"}, "terminationGracePeriodSeconds": 10,
                "domain": {"cpu": {"model": "host-passthrough", "cores": 2}, "memory": {"guest": "8Gi"},
                    "resources": {"requests": {"memory": "8Gi"}}, "firmware": {"bootloader": {"efi": {"secureBoot": False}}},
                    "launchSecurity": {"tdx": {}}, "devices": {"autoattachVSOCK": True, "logSerialConsole": True, "rng": {},
                        "disks": [{"name": "rootdisk", "disk": {"bus": "virtio", "readonly": True}}, {"name": "opkey", "disk": {"bus": "virtio"}}],
                        "interfaces": [{"name": "default", "masquerade": {}}]}},
                "networks": [{"name": "default", "pod": {}}], "volumes": [
                    {"name": "rootdisk", "persistentVolumeClaim": {"claimName": self.name + "-root"}},
                    {"name": "opkey", "secret": {"secretName": self.name + "-opkey", "volumeLabel": "opkeydata"}}]}}}}

    def capture(self, index, deadline=None):
        def read(*args, **kwargs):
            return kube(*args, timeout=budget(deadline), **kwargs)

        vm = self.get("vm", "", deadline)
        write(self.evidence / f"{index:03}-vm.json", vm)
        vmi = read("get", "vmi", self.name, "--ignore-not-found", "-o", "json")
        if not vmi:
            return False
        uid = vmi["metadata"]["uid"]
        require(any(r.get("controller") and r.get("kind") == "VirtualMachine" and r.get("uid") == vm["metadata"]["uid"]
                    for r in vmi["metadata"].get("ownerReferences", [])), "VMI owner differs")
        write(self.evidence / f"{index:03}-vmi.json", vmi)
        pods = read("get", "pods", "-l", "kubevirt.io/domain=" + self.name, "-o", "json")["items"]
        for pod in pods:
            meta = pod["metadata"]
            require(any(r.get("controller") and r.get("kind") == "VirtualMachineInstance" and r.get("uid") == uid
                        for r in meta.get("ownerReferences", [])), "launcher owner differs")
            write(self.evidence / f"{index:03}-launcher.json", pod)
            for kind, args in [("serial", ["exec", meta["name"], "-c", "compute", "--", "head", "-c", "262144", "/var/run/kubevirt-private/" + uid + "/virt-serial0-log"]),
                               ("compute.log", ["logs", meta["name"], "-c", "compute", "--tail=500", "--limit-bytes=262144", "--timestamps=true"])]:
                try:
                    data = read(*args, raw=True)
                    require(len(data) <= 262144, "oversized diagnostic output")
                    require(read("get", "pod", meta["name"], "-o", "json")["metadata"]["uid"] == meta["uid"], "launcher replaced during capture")
                    require(read("get", "vmi", self.name, "-o", "json")["metadata"]["uid"] == uid, "VMI replaced during capture")
                    write(self.evidence / f"{index:03}-{kind}", data)
                except (RuntimeError, subprocess.TimeoutExpired) as error:
                    write(self.evidence / f"{index:03}-{kind}-error.json", {"error": str(error)})
        return vmi.get("status", {}).get("phase") in ("Failed", "Succeeded")

    def observe(self):
        deadline = time.monotonic() + 600
        for index in range(40):
            if self.capture(index, deadline) or time.monotonic() >= deadline:
                break
            pause(deadline, 10)
        logs = list(self.evidence.glob("*-serial")) + list(self.evidence.glob("*-compute.log"))
        require(any(path.stat().st_size for path in logs), "no serial or launcher log was captured; inspect native status evidence")

    def remove(self, kind, suffix):
        entry = next(e for e in self.resources() if e["kind"] == kind and e["suffix"] == suffix)
        obj = kube("get", kind, self.name + suffix, "--ignore-not-found", "-o", "json")
        if obj:
            self.owned(obj, suffix, entry["uid"])
            # Preconditions prevent deleting a replacement after the ownership check.
            plural = {"vm": "virtualmachines", "pod": "pods", "pvc": "persistentvolumeclaims", "secret": "secrets"}[kind]
            base = "/apis/kubevirt.io/v1" if kind == "vm" else "/api/v1"
            url = f"{base}/namespaces/{NS}/{plural}/{self.name}{suffix}"
            options = {"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": obj["metadata"]["uid"]}, "propagationPolicy": "Foreground"}
            kube("delete", "--raw", url, "-f", "-", data=json.dumps(options).encode(), raw=True)
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            if kube("get", kind, self.name + suffix, "--ignore-not-found", "-o", "json", timeout=budget(deadline)) is None:
                return
            pause(deadline, 5)
        raise RuntimeError("resource deletion did not complete: " + kind + suffix)

    def cleanup(self):
        errors = []
        for entry in reversed(self.resources()):
            try:
                self.remove(entry["kind"], entry["suffix"])
            except Exception as error:
                errors.append(str(error))
                # Keep the disks and Secret if the VM could still be using them.
                if entry["kind"] == "vm":
                    break
        write(self.evidence / "cleanup.json", {"name": self.name, "complete": not errors, "errors": errors})
        require(not errors, "cleanup incomplete; retained ownership ledger")


def main():
    os.umask(0o077)
    require(len(sys.argv) == 2 and sys.argv[1] in ("run", "cleanup"), "expected run or cleanup")
    root = Path(os.environ["RUNNER_TEMP"]) / "pod-diagnostic"
    task = Diagnostic(root, os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_RUN_ATTEMPT"], os.environ["GITHUB_REPOSITORY"])
    if sys.argv[1] == "cleanup":
        task.cleanup()
        return
    require(not task.resources(), "diagnostic run already owns resources")
    try:
        task.prepare()
        task.provision()
        task.observe()
    except BaseException as error:
        write(task.evidence / "failure.json", {"error": str(error), "type": type(error).__name__})
        if any(entry["kind"] == "vm" for entry in task.resources()):
            try:
                task.capture(999, time.monotonic() + 60)
            except Exception as capture_error:
                write(task.evidence / "failure-capture.json", {"error": str(capture_error)})
        raise
    print("Boot evidence captured; this diagnostic does not establish image or Pod connectivity acceptance.")


if __name__ == "__main__":
    main()
