#!/usr/bin/env python3
"""Manual connected native TDX acceptance; never Cloud API/provider conformance."""
import base64
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time
import urllib.request

from tdx_pod_resources import NS, OwnedResources, budget, command, kube, pause, require, write

FIXTURE = Path(__file__).resolve().parent / "fixtures/pod-connected"
PAUSE = "docker.io/rancher/mirrored-pause:3.10.2@sha256:f548e0e8e3dc1896ca956272154dde3314e8cc4fde0a57577ee9fa1c63f5baf4"
SIDES = ("server", "a", "b")
SOAK = 65 * 60


def validate_pins(pins):
    require(pins.get("schema") == 1 and re.fullmatch(r"[0-9a-f]{40}", pins.get("source", "")), "invalid production source pin")
    require(pins.get("profileSource") == pins["source"], "image profile and components must match")
    require(re.fullmatch(r"[1-9][0-9]*", pins.get("buildRun", "")), "invalid image build run")
    for key in ("image", "artifact"):
        require(re.fullmatch(r"ghcr.io/confidential-dot-ai/node-guest-base@sha256:[0-9a-f]{64}", pins.get(key, "")), "unbound image reference")
    for key in ("manifestSHA256", "diskSHA256"):
        require(re.fullmatch(r"[0-9a-f]{64}", pins.get(key, "")), "invalid image digest")
    require(re.fullmatch(r"ghcr.io/confidential-dot-ai/armtls-mesh@sha256:[0-9a-f]{64}", pins.get("meshImage", "")), "unbound mesh image")


def validate_manifest(raw, pins):
    validate_pins(pins)
    require(len(raw) <= 65536 and hashlib.sha256(raw).hexdigest() == pins["manifestSHA256"], "production manifest digest differs")
    data = json.loads(raw)
    require(data.get("build", {}).get("platform") == "tdx", "production manifest is not TDX")
    require(data["inputs"]["base_image"]["sha256"] == pins["diskSHA256"], "production disk differs")
    require(data["outputs"]["disk_image"]["sha256"] == pins["diskSHA256"], "published disk differs")
    require(all(re.fullmatch(r"[0-9a-f]{96}", data["tdx"][key]) for key in ("mrtd", "rtmr1", "rtmr2")), "incomplete TDX identity")
    return data


def pod_state(status, uid):
    require(status.get("metadata", {}).get("uid") == uid, "attested Pod UID differs")
    states = {item["name"]: item for item in status.get("status", {}).get("containerStatuses", [])}
    if not states:
        return {"ready": False, "complete": False, "running": False, "starts": {}}
    require(set(states) == {"app", "checker"}, "unexpected signed workload container")
    endpoints = {item["name"]: item for item in status.get("status", {}).get("initContainerStatuses", [])}
    require(set(endpoints) == {"c8s-mesh-endpoint"}, "expected measured mesh endpoint is missing")
    states.update(endpoints)
    require(all(item.get("restartCount", 0) == 0 for item in states.values()), "workload restarted")
    require(all("terminated" not in states[name].get("state", {}) for name in ("app", "c8s-mesh-endpoint")), "application or mesh endpoint exited")
    ended = states["checker"].get("state", {}).get("terminated")
    require(ended is None or ended.get("exitCode") == 0, "network acceptance checker failed")
    starts = {name: (item.get("state", {}).get("running") or item.get("state", {}).get("terminated") or {}).get("startedAt") for name, item in states.items()}
    running = all("running" in item.get("state", {}) and starts[name] for name, item in states.items())
    return {"ready": all(states[name].get("ready", False) and "running" in states[name].get("state", {}) for name in ("app", "c8s-mesh-endpoint")), "complete": ended is not None, "running": bool(running), "starts": starts}


def renewed(initial, current):
    require(initial["sandboxID"] == current["sandboxID"], "Pod identity changed during renewal")
    require(current["workload"] == "connected" and current["denied"] is True, "named leaf missing or certless access succeeded")
    return initial["serial"] != current["serial"] and initial["spki"] != current["spki"]


def renewal_event(previous, current, elapsed):
    changed = renewed(previous, current)
    before = lambda leaf: datetime.fromisoformat(leaf["notBefore"].replace("Z", "+00:00"))
    after = lambda leaf: datetime.fromisoformat(leaf["notAfter"].replace("Z", "+00:00"))
    # A new transition after steady runtime, not an early replacement still served later.
    # The guest's one-hour timer allows downward jitter; forty minutes is below its floor.
    return changed and elapsed >= 2400 and (before(current) - before(previous)).total_seconds() >= 2400 and after(current) > after(previous)


def readiness_cycle(values):
    transitions = [value for i, value in enumerate(values) if i == 0 or value != values[i-1]]
    if transitions and transitions[0] is False:
        transitions = transitions[1:]
    return transitions == [True, False, True]


class Acceptance(OwnedResources):
    def __init__(self, *args):
        super().__init__(*args)
        self.pins = json.loads((FIXTURE / "production-image.json").read_text())
        self.cli = self.private / "c8s"
        self.probe = self.private / "pod-mesh-probe"
        self.bundle = self.private / "bundle"
        self.forwards, self.connections, self.vmi_uids = [], {}, {}
        self.run_deadline = time.monotonic() + 123 * 60

    def deadline(self, seconds):
        return min(self.run_deadline, time.monotonic() + seconds)

    def prepare(self):
        validate_pins(self.pins)
        source = Path(os.environ["POD_ACCEPTANCE_SOURCE"])
        require(command(["git", "-C", source, "rev-parse", "HEAD"]).decode().strip() == self.pins["source"], "CLI source does not match production image")
        require(not command(["git", "-C", source, "status", "--porcelain"]).strip(), "paired CLI checkout is dirty")
        headers = {}
        token = os.environ.get("GH_TOKEN")
        if token:
            credentials = base64.b64encode((os.environ["GITHUB_ACTOR"] + ":" + token).encode()).decode()
            headers["Authorization"] = "Basic " + credentials
        auth = urllib.request.Request("https://ghcr.io/token?service=ghcr.io&scope=repository:confidential-dot-ai/node-guest-base:pull", headers=headers)
        with urllib.request.urlopen(auth, timeout=30) as response:
            bearer = json.load(response)["token"]
        url = "https://ghcr.io/v2/confidential-dot-ai/node-guest-base/blobs/sha256:" + self.pins["manifestSHA256"]
        with urllib.request.urlopen(urllib.request.Request(url, headers={"Authorization": "Bearer " + bearer}), timeout=60) as response:
            raw = response.read(65537)
        validate_manifest(raw, self.pins)
        write(self.private / "manifest.json", raw)
        write(self.evidence / "manifest.json", raw)
        write(self.evidence / "image.json", self.pins)
        for resource in ("services", "virtualmachines.kubevirt.io", "persistentvolumeclaims", "secrets"):
            require(kube("auth", "can-i", "create", resource, raw=True).strip() == b"yes", "missing scoped create authority: " + resource)
        self.services()
        command(["python3", FIXTURE / "stage.py", "bundle", "--name", self.name, "--namespace", NS,
                 "--out", self.bundle, "--services", self.private / "services.json", "--cli", self.cli,
                 "--manifest", self.private / "manifest.json", "--manifest-sha256", self.pins["manifestSHA256"],
                 "--source", self.pins["source"], "--mesh-image", self.pins["meshImage"]], timeout=180)
        self.identity = json.loads((self.bundle / "identity.json").read_text())
        write(self.evidence / "identity.json", self.identity)

    def services(self):
        command(["python3", FIXTURE / "stage.py", "services", "--name", self.name, "--namespace", NS, "--out", self.private / "service-inputs.json"])
        items = []
        for spec in json.loads((self.private / "service-inputs.json").read_text())["items"]:
            suffix = spec["metadata"]["name"].removeprefix(self.name)
            items.append(self.create("service", suffix, spec))
        write(self.private / "services.json", {"items": items})
        write(self.evidence / "services.json", {"items": items})

    def pvc(self, suffix):
        return self.create("pvc", suffix, {"apiVersion": "v1", "kind": "PersistentVolumeClaim", "spec": {
            "accessModes": ["ReadWriteOnce"], "storageClassName": "local-path", "resources": {"requests": {"storage": "80Gi"}}}})

    def import_root(self):
        self.pvc("-root")
        binder = {"apiVersion": "v1", "kind": "Pod", "spec": {
            "restartPolicy": "Never", "activeDeadlineSeconds": 1500, "automountServiceAccountToken": False,
            "nodeSelector": {"kubevirt.io/tdx": "true"},
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{"name": "pause", "image": PAUSE, "resources": {"requests": {"cpu": "8", "memory": "32Gi"}, "limits": {"cpu": "8", "memory": "32Gi"}},
                "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}}}],
            "volumes": [{"name": "root", "persistentVolumeClaim": {"claimName": self.name + "-root", "readOnly": True}}]}}
        self.create("pod", "-binder", binder)
        deadline = self.deadline(300)
        while time.monotonic() < deadline:
            pvc, pod = self.get("pvc", "-root", deadline), self.get("pod", "-binder", deadline)
            if pod.get("spec", {}).get("nodeName") and pvc.get("status", {}).get("phase") == "Bound":
                require(pvc["metadata"]["annotations"]["volume.kubernetes.io/selected-node"] == pod["spec"]["nodeName"], "root selected another node")
                break
            pause(deadline)
        else:
            raise RuntimeError("TDX capacity binder did not schedule")
        kube("annotate", "pvc", self.name + "-root", "--resource-version=" + pvc["metadata"]["resourceVersion"],
             "cdi.kubevirt.io/storage.import.source=registry", "cdi.kubevirt.io/storage.import.endpoint=docker://" + self.pins["image"],
             "cdi.kubevirt.io/storage.contentType=kubevirt", "cdi.kubevirt.io/storage.import.secretName=ghcr-pull", raw=True)
        self.remove("pod", "-binder")
        deadline = self.deadline(1200)
        while time.monotonic() < deadline:
            phase = self.get("pvc", "-root", deadline)["metadata"].get("annotations", {}).get("cdi.kubevirt.io/storage.pod.phase")
            require(phase != "Failed", "production root import failed")
            if phase == "Succeeded":
                return
            pause(deadline, 10)
        raise RuntimeError("production root import timed out")

    def vm(self, side):
        disks = [{"name": "rootdisk", "disk": {"bus": "virtio", "readonly": True}}, {"name": "opkey", "disk": {"bus": "virtio"}}]
        volumes = [{"name": "rootdisk", "persistentVolumeClaim": {"claimName": self.name + "-root"}},
                   {"name": "opkey", "secret": {"secretName": self.name + "-" + side + "-opkey", "volumeLabel": "opkeydata"}}]
        if side == "server":
            disks.append({"name": "scratch", "disk": {"bus": "virtio"}, "serial": "confai-scratch"})
            volumes.append({"name": "scratch", "persistentVolumeClaim": {"claimName": self.name + "-scratch"}})
        memory, cores = ("16Gi", 4) if side == "server" else ("8Gi", 2)
        return {"apiVersion": "kubevirt.io/v1", "kind": "VirtualMachine", "spec": {"runStrategy": "Once", "template": {
            "metadata": {"labels": {"kubevirt.io/domain": self.name + "-" + side}}, "spec": {
                "nodeSelector": {"kubevirt.io/tdx": "true"}, "terminationGracePeriodSeconds": 10,
                "domain": {"cpu": {"model": "host-passthrough", "cores": cores}, "memory": {"guest": memory}, "resources": {"requests": {"memory": memory}},
                    "firmware": {"bootloader": {"efi": {"secureBoot": False}}}, "launchSecurity": {"tdx": {}},
                    "devices": {"autoattachVSOCK": True, "logSerialConsole": True, "rng": {}, "disks": disks,
                                "interfaces": [{"name": "default", "masquerade": {}}]}},
                "networks": [{"name": "default", "pod": {}}], "volumes": volumes}}}}

    def provision(self):
        self.import_root()
        self.pvc("-scratch")
        for spec in json.loads((self.bundle / "opkey-secrets.json").read_text())["items"]:
            self.create("secret", spec["metadata"]["name"].removeprefix(self.name), spec)
        for side in SIDES:
            self.create("vm", "-" + side, self.vm(side))
        deadline = self.deadline(600)
        while time.monotonic() < deadline:
            if all(self.instance(side, deadline).get("status", {}).get("phase") == "Running" for side in SIDES):
                return
            pause(deadline, 10)
        raise RuntimeError("three owned TDX VMIs did not reach Running")

    def instance(self, side, deadline=None):
        vm = self.get("vm", "-" + side, deadline)
        vmi = kube("get", "vmi", self.name + "-" + side, "--ignore-not-found", "-o", "json", timeout=budget(deadline))
        if not vmi:
            return {}
        require(any(ref.get("controller") and ref.get("kind") == "VirtualMachine" and ref.get("uid") == vm["metadata"]["uid"]
                    for ref in vmi["metadata"].get("ownerReferences", [])), "VMI owner differs")
        old = self.vmi_uids.setdefault(side, vmi["metadata"]["uid"])
        require(old == vmi["metadata"]["uid"], "VMI replaced during acceptance")
        require(vmi.get("status", {}).get("phase") not in ("Failed", "Succeeded"), "guest stopped during acceptance")
        return vmi

    def connect(self, side, port):
        self.get("service", "-" + side)
        self.instance(side)
        address = self.identity["services"][side]["ip"]
        try:
            with socket.create_connection((address, port), timeout=2):
                self.connections[side, port] = address + ":" + str(port)
                return
        except OSError:
            pass
        try:
            forward_allowed = kube("auth", "can-i", "get", "virtualmachineinstances.subresources.kubevirt.io", "--subresource=portforward", raw=True).strip() == b"yes"
        except RuntimeError:
            forward_allowed = False
        if not forward_allowed:
            # Running VMIs may still be booting; the bounded warmup retries the direct route.
            self.connections[side, port] = address + ":" + str(port)
            return
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            local = sock.getsockname()[1]
        # A held VMI UID and ownership checks fence this read-only transport.
        log = open(self.private / f"forward-{side}-{port}.log", "wb")
        proc = subprocess.Popen(["virtctl", "-n", NS, "port-forward", "vmi/" + self.name + "-" + side,
                                 str(local) + ":" + str(port), "--address", "127.0.0.1"], stdout=log, stderr=subprocess.STDOUT)
        self.forwards.append((proc, log))
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            require(proc.poll() is None, "owned VMI port-forward exited")
            try:
                with socket.create_connection(("127.0.0.1", local), timeout=1):
                    self.instance(side)
                    self.connections[side, port] = "127.0.0.1:" + str(local)
                    return
            except OSError:
                pause(deadline, 1)
        raise RuntimeError("owned VMI port-forward did not listen")

    def stop_forwards(self):
        for process, log in self.forwards:
            if process.poll() is not None:
                log.close()
                continue
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            log.close()

    def cli_read(self, side, mode, deadline=None):
        argv = [self.cli, *mode, "--node", self.connections[side, 8443], "--launch-key-pub", self.bundle / side / "pod/pubkey",
                "--image-manifest", self.private / "manifest.json", "--timeout", "45s"]
        if mode == ["pod-attest"]:
            for digest in self.identity["expectedDigests"]:
                argv += ["--expect-digest", digest]
        raw = command(argv, timeout=budget(deadline, 50))
        require(len(raw) <= 65536, "oversized authenticated response")
        return json.loads(raw)

    def leaf(self, side, mode="certless"):
        raw = command([self.probe, "--address", self.connections[side, 8080], "--ca", self.evidence / "mesh-ca.pem", "--mode", mode], timeout=15)
        require(len(raw) <= 8192, "oversized mesh observation")
        return json.loads(raw)

    def ca(self, path, deadline):
        command([self.cli, "cds", "ca", "--url", "https://" + self.connections["server", 30808],
                 "--image-policy-file", self.bundle / "server/server.json", "--out", path], timeout=budget(deadline, 50))

    def observe(self):
        for side in SIDES:
            for port in ([30808] if side == "server" else [8443, 8080]):
                self.connect(side, port)
        write(self.evidence / "transport.json", {"runner": {side + ":" + str(port): endpoint for (side, port), endpoint in self.connections.items()},
              "guestTraffic": "the three signed ClusterIP Services; port-forwards are runner observation only"})
        deadline = self.deadline(1200)
        initial, traces, states = {}, {"a": [], "b": []}, {}
        while time.monotonic() < deadline:
            try:
                initial = {}
                self.ca(self.evidence / "mesh-ca.pem", deadline)
                for side in ("a", "b"):
                    report = self.cli_read(side, ["pod-attest"], deadline)
                    status = self.cli_read(side, ["pod-status", "get"], deadline)
                    state = pod_state(status, self.name)
                    traces[side].append(state["ready"])
                    states[side] = state
                    write(self.evidence / (side + "-initial-attestation.json"), report)
                    write(self.evidence / (side + "-initial-status.json"), status)
                    candidate = self.leaf(side)
                    if candidate["workload"] == "connected" and state["running"]:
                        initial[side] = candidate
                if set(initial) == {"a", "b"}:
                    break
            except (RuntimeError, subprocess.TimeoutExpired, OSError) as error:
                write(self.evidence / "warmup-last-error.json", {"error": str(error)})
            pause(deadline, 10)
        require(set(initial) == {"a", "b"}, "both Pods did not obtain named CDS leaves")
        require(initial["a"]["sandboxID"] != initial["b"]["sandboxID"], "two guests share a mesh instance identity")
        write(self.evidence / "initial-leaves.json", initial)
        ca_bytes = (self.evidence / "mesh-ca.pem").read_bytes()
        start = time.monotonic()
        require(self.run_deadline - start >= SOAK + 360, "insufficient budget for full renewal observation")
        deadline = self.deadline(SOAK + 600)
        baseline_starts = {side: states[side]["starts"] for side in ("a", "b")}
        previous = dict(initial)
        rotations = {"a": False, "b": False}
        index = 0
        while time.monotonic() < deadline:
            index += 1
            sample = {"elapsed": time.monotonic() - start, "pods": {}}
            for side in ("a", "b"):
                self.instance(side, deadline)
                status = self.cli_read(side, ["pod-status", "get"], deadline)
                state = pod_state(status, self.name)
                states[side] = state
                traces[side].append(state["ready"])
                leaf = self.leaf(side)
                # A checker exit can itself refresh claims; it is not timed renewal.
                require(state["starts"] == baseline_starts[side], "attested container start identity changed")
                rotation = renewal_event(previous[side], leaf, time.monotonic() - start)
                rotations[side] |= rotation and state["running"]
                previous[side] = leaf
                sample["pods"][side] = {"status": status, "leaf": leaf}
            write(self.evidence / f"sample-{index:03}.json", sample)
            if time.monotonic() - start >= SOAK and all(rotations.values()) and all(s["complete"] for s in states.values()):
                break
            pause(deadline, 20)
        require(time.monotonic() - start >= SOAK and all(rotations.values()), "65-minute named credential rotation was not established")
        require(all(s["complete"] and s["ready"] for s in states.values()), "final attested network checker or app readiness failed")
        for side in ("a", "b"):
            # Compress repeats and require ready -> unready -> ready while the app lives.
            require(readiness_cycle(traces[side]), "attested readiness did not recover or had an unexpected outage")
            for mode in ("certless", "wrong-ca", "plaintext"):
                write(self.evidence / f"{side}-negative-{mode}.json", self.leaf(side, mode))
            write(self.evidence / (side + "-final-attestation.json"), self.cli_read(side, ["pod-attest"], deadline))
        pause(deadline, 95)
        for side in ("a", "b"):
            final_status = self.cli_read(side, ["pod-status", "get"], deadline)
            final_state = pod_state(final_status, self.name)
            require(final_state["ready"] and final_state["complete"] and final_state["starts"] == baseline_starts[side], "post-negative authenticated workload health failed")
            write(self.evidence / (side + "-final-status.json"), final_status)
        self.ca(self.private / "final-ca.pem", deadline)
        require((self.private / "final-ca.pem").read_bytes() == ca_bytes, "CDS mesh CA changed during acceptance")
        write(self.evidence / "result.json", {"schema": 1, "passed": True, "scope": "native TDX; not Cloud API acceptance",
              "elapsedAfterNamedLeaves": time.monotonic() - start, "rotated": rotations, "readiness": traces,
              "networkReceipt": "both authenticated checker exit codes zero and applications still ready"})

    def capture(self):
        deadline = time.monotonic() + 90
        for side in SIDES:
            if not any(e["kind"] == "vm" and e["suffix"] == "-" + side for e in self.resources()):
                continue
            try:
                vm = self.get("vm", "-" + side, deadline)
                write(self.evidence / (side + "-vm.json"), vm)
                vmi = kube("get", "vmi", self.name + "-" + side, "--ignore-not-found", "-o", "json", timeout=budget(deadline))
                if not vmi:
                    continue
                uid = vmi["metadata"]["uid"]
                require(any(r.get("controller") and r.get("kind") == "VirtualMachine" and r.get("uid") == vm["metadata"]["uid"] for r in vmi["metadata"].get("ownerReferences", [])), "capture VMI owner differs")
                write(self.evidence / (side + "-vmi.json"), vmi)
                pods = kube("get", "pods", "-l", "kubevirt.io/domain=" + self.name + "-" + side, "-o", "json", timeout=budget(deadline))["items"]
                for pod in pods:
                    meta = pod["metadata"]
                    require(any(r.get("controller") and r.get("kind") == "VirtualMachineInstance" and r.get("uid") == uid for r in meta.get("ownerReferences", [])), "capture launcher owner differs")
                    write(self.evidence / (side + "-launcher.json"), pod)
                    for label, args in [("serial", ["exec", meta["name"], "-c", "compute", "--", "head", "-c", "262144", "/var/run/kubevirt-private/" + uid + "/virt-serial0-log"]),
                                        ("compute.log", ["logs", meta["name"], "-c", "compute", "--tail=500", "--limit-bytes=262144", "--timestamps=true"])]:
                        try:
                            raw = kube(*args, raw=True, timeout=budget(deadline))
                            require(len(raw) <= 262144, "oversized boot capture")
                            require(kube("get", "pod", meta["name"], "-o", "json", timeout=budget(deadline))["metadata"]["uid"] == meta["uid"], "launcher replaced during capture")
                            write(self.evidence / (side + "-" + label), raw)
                        except Exception as error:
                            write(self.evidence / (side + "-" + label + "-error.json"), {"error": str(error)})
            except Exception as error:
                write(self.evidence / (side + "-capture-error.json"), {"error": str(error)})


def main():
    os.umask(0o077)
    require(len(sys.argv) == 2 and sys.argv[1] in ("run", "cleanup"), "expected run or cleanup")
    task = Acceptance(Path(os.environ["RUNNER_TEMP"]) / "pod-acceptance", os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_RUN_ATTEMPT"], os.environ["GITHUB_REPOSITORY"])
    if sys.argv[1] == "cleanup":
        task.cleanup()
        return
    require(not task.resources(), "acceptance already owns resources")
    try:
        task.prepare()
        task.provision()
        task.observe()
    except BaseException as error:
        write(task.evidence / "failure.json", {"error": str(error), "type": type(error).__name__})
        raise
    finally:
        for action, name in ((task.capture, "capture"), (task.stop_forwards, "forward-cleanup")):
            try:
                action()
            except Exception as error:
                write(task.evidence / (name + "-error.json"), {"error": str(error)})
    print("Native TDX connected acceptance passed; this is not Cloud API acceptance.")


if __name__ == "__main__":
    main()
