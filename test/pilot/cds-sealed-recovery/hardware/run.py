#!/usr/bin/env python3
"""Sequential disposable SNP qualification, with durable UID-scoped cleanup.

Uses the existing Cloud rehearsal HTTP/kubeconfig helpers, the native ConfAI
fixture renderer and kubectl/virtctl. Never updates a shared resource. This is
a hardware primitive test, not the three-backend public Cloud API rehearsal.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import subprocess
import sys
import tarfile
import time

NS = "p-internal"
LABEL = "cloud.confidential.ai/qualification-owner"
KINDS = {"PersistentVolumeClaim": ("/api/v1", "persistentvolumeclaims"),
         "Secret": ("/api/v1", "secrets"), "Pod": ("/api/v1", "pods"),
         "NetworkPolicy": ("/apis/networking.k8s.io/v1", "networkpolicies"),
         "VirtualMachine": ("/apis/kubevirt.io/v1", "virtualmachines")}
VMI = f"/apis/kubevirt.io/v1/namespaces/{NS}/virtualmachineinstances"


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def digest(path):
    with Path(path).open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def archive_receiver(size, destination, completion=""):
    need(isinstance(size, int) and 0 < size <= 8 * 1024**3, "invalid archive byte bound")
    need(not completion or re.fullmatch(r"[0-9a-f]{32}", completion), "invalid completion token")
    # Some exec proxies leave remote stdin open after the local file ends.
    # Frame the transfer explicitly so gzip sees EOF after these exact bytes.
    # Values travel as quoted positional arguments, never shell source.
    # Expansion can take longer than a streaming proxy's idle timeout under
    # the population Pod's CPU limit. GNU tar reports actual extraction work
    # every 10 MiB; progress never substitutes for the later artifact hashes.
    return ["sh", "-c", 'head -c "$1" | tar --checkpoint=1024 --checkpoint-action=echo -xz -C "$2" && '
            '{ [ -z "$3" ] || printf "%s" "$3" > "$2/.cds-upload-complete"; }',
            "archive-receiver", str(size), destination, completion]


def image_inputs(directory):
    p = Path(directory)
    manifest = json.loads((p / "manifest.json").read_text())
    need(manifest["version"] == 3 and manifest["build"]["memory"] == "4G", "4G manifest v3 required")
    variants = [x for x in manifest["snp_variants"] if x["smp"] == 2]
    need(len(variants) == 1, "one independently measured 2-vCPU variant required")
    variant = variants[0]
    measurement = variant["measurement"]["snp_launch_digest"]
    need(re.fullmatch(r"[0-9a-f]{96}", measurement) and set(measurement) != {"0"}, "invalid SNP measurement")
    entries = [(manifest["outputs"]["disk_image"], "disk.raw"),
               (variant["igvm"], "guest-smp2.igvm"),
               (manifest["outputs"]["uki"], "uki.efi"),
               (manifest["inputs"]["firmware"], "OVMF.fd")]
    for entry, name in entries:
        need(entry["path"] == name and re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]), "unexpected artifact path/hash")
        need(digest(p / name) == entry["sha256"], "artifact hash mismatch: " + name)
    need((p / "disk.raw").stat().st_size < 8 * 1024**3, "root disk exceeds owned claim")
    return measurement, {name: entry["sha256"] for entry, name in entries}


def resource_path(item):
    meta = item["metadata"]
    need(meta["namespace"] == NS and item["kind"] in KINDS, "resource outside fixture scope")
    run = meta["labels"][LABEL]
    need(re.fullmatch(r"cds-(snp|tdx)-[0-9a-f]{12}", run) and
         meta["name"] in (run, run + "-root", run + "-boot", run + "-opkey", run + "-populate"), "invalid owned name")
    prefix, plural = KINDS[item["kind"]]
    return f"{prefix}/namespaces/{NS}/{plural}/{meta['name']}"


def check_probe_network_policy(item, run):
    resource_path(item)
    need(item["kind"] == "NetworkPolicy" and item["metadata"]["name"] == run and item["spec"] == {
        "podSelector": {"matchLabels": {LABEL: run, "kubevirt.io/domain": run}},
        "policyTypes": ["Ingress"],
        "ingress": [{"ports": [{"protocol": "TCP", "port": 6443}], "from": [{
            "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kubevirt"}},
            "podSelector": {"matchLabels": {"kubevirt.io": "virt-api"}}}]}]},
        "network policy must permit only KubeVirt API TCP 6443 to the owned probe")


class RetryReads:
    """Retry only transient server failures of an unchanged GET request.

    Writes retain the existing UID reconciliation path. A retry is never
    evidence of success, and authentication or validation failures stop at once.
    """
    def __init__(self, client, event):
        self.client, self.event = client, event

    def call(self, method, path, *args, **kwargs):
        for attempt in range(3):
            try:
                return self.client.call(method, path, *args, **kwargs)
            except Exception as error:
                transient = method == "GET" and str(error) in {
                    f"GET {path.split('?')[0]} returned HTTP {code}" for code in (500, 502, 503, 504)}
                if not transient or attempt == 2:
                    raise
                self.event("api-read-retry", path=path.split('?')[0],
                           reason=str(error), attempt=attempt + 1)
                time.sleep(attempt + 1)


class Run:
    def __init__(self, args, kube, atomic_json):
        self.args, self.atomic = args, atomic_json
        self.directory = Path(args.directory)
        self.path = self.directory / "journal.json"
        self.state = json.loads(self.path.read_text()) if self.path.exists() else {
            "version": 1, "resources": [], "events": [], "full_acceptance_passed": False,
            "production_ready": False, "hardware_primitive_passed": False}
        need(self.state.get("version") == 1, "unknown ownership journal version")
        self.forward = None
        self.kube = RetryReads(kube, self.event)

    def save(self):
        self.atomic(self.path, self.state)

    def event(self, name, **fields):
        event = {"time": dt.datetime.now(dt.timezone.utc).isoformat(), "event": name, **fields}
        self.state["events"].append(event)
        self.save()
        print(json.dumps(event), flush=True)

    def command(self, name, argv, *, data=None, timeout=120):
        with (self.directory / (name + ".stderr")).open("wb") as err:
            r = subprocess.run(argv, stdin=data, stdout=subprocess.PIPE, stderr=err, timeout=timeout)
        (self.directory / (name + ".stdout")).write_bytes(r.stdout)
        need(r.returncode == 0, f"{name} failed; see its private log")
        return r.stdout

    def kubectl(self, *args):
        return [self.args.kubectl, "--kubeconfig", self.args.kubeconfig, "-n", NS, *args]

    def upload(self, pod, archive, destination):
        # Some exec streaming paths deliver all input but never deliver the
        # command's exit status. Require a fresh receiver-completion token over
        # a separate authenticated exec, then verify artifact hashes below.
        # A transport timeout alone can never establish a completed upload.
        name = pod + "-" + archive
        token = secrets.token_hex(16)
        with (self.directory / archive).open("rb") as data, \
             (self.directory / (name + ".stdout")).open("wb") as out, \
             (self.directory / (name + ".stderr")).open("wb") as err:
            receiver = archive_receiver(os.fstat(data.fileno()).st_size, destination, token)
            process = subprocess.Popen(self.kubectl("exec", "-i", pod, "--", *receiver),
                                       stdin=data, stdout=out, stderr=err)
            try:
                deadline = time.monotonic() + 300
                while time.monotonic() < deadline:
                    try:
                        marker = self.command(name + "-completion", self.kubectl("exec", pod, "--",
                            "sh", "-c", 'if [ -f "$1" ]; then cat "$1"; fi', "upload-completion",
                            destination + "/.cds-upload-complete"), timeout=20)
                    except (RuntimeError, subprocess.TimeoutExpired) as error:
                        # This read may lose its API connection independently
                        # of the upload. Retry within the original deadline;
                        # only the exact fresh token can establish completion.
                        self.event("upload-completion-unavailable", archive=archive,
                                   failure=type(error).__name__)
                        time.sleep(5)
                        continue
                    if marker == token.encode():
                        self.event("upload-receiver-completed", archive=archive,
                                   client_exit_pending=process.poll() is None,
                                   client_returncode=process.poll())
                        return
                    need(not marker, "unexpected upload completion token")
                    # A lost stream can leave the receiver finishing data it
                    # already received. Only its fresh token and the later
                    # hashes establish completion, within this same deadline.
                    time.sleep(5)
                raise TimeoutError("upload receiver completion timed out")
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()

    def wait_absent(self, path, timeout=120):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            code, _ = self.kube.call("GET", path, expected=(200, 404))
            if code == 404:
                return
            time.sleep(2)
        raise RuntimeError("owned resource did not disappear: " + path)

    def create(self, item):
        path = resource_path(item)
        code, _ = self.kube.call("GET", path, expected=(200, 404))
        need(code == 404, "refusing existing resource: " + path)
        row = {"item": item, "path": path, "uid": None}
        self.state["cleanup_verified"] = False
        self.state["resources"].append(row)
        self.save()  # creation intent survives a lost POST response
        for attempt in range(3):
            code, created = self.kube.call("POST", path.rsplit("/", 1)[0], item,
                                          expected=(201, 500, 502, 503, 504))
            if code != 201:
                self.event("create-unavailable", path=path, http_status=code, attempt=attempt + 1)
                # A server error does not prove the write failed. Reconcile
                # the recorded intent before retrying the same object name.
                code, created = self.kube.call("GET", path, expected=(200, 404))
                if code == 404:
                    if attempt < 2:
                        time.sleep(2 * (attempt + 1))
                    continue
            meta = created["metadata"]
            need(meta.get("labels", {}).get(LABEL) == item["metadata"]["labels"][LABEL],
                 "create response owner mismatch")
            row["uid"] = meta["uid"]
            self.save()
            return row
        raise RuntimeError("owned create failed after three transient API responses: " + path)

    def remove(self, row):
        need(row["path"] == resource_path(row["item"]), "journal path outside owned scope")
        if row.get("deleted"):
            return
        code, current = self.kube.call("GET", row["path"], expected=(200, 404))
        if code == 404:
            if row.get("pv"):
                self.wait_absent("/api/v1/persistentvolumes/" + row["pv"]["name"])
            row["deleted"] = True
            self.save()
            return
        meta, original = current["metadata"], row["item"]["metadata"]
        need(meta.get("labels", {}).get(LABEL) == original["labels"][LABEL], "cleanup owner mismatch")
        if row["uid"] is None:
            row["uid"] = meta["uid"]  # recover this run's durable creation intent
            self.save()
        need(meta["uid"] == row["uid"], "cleanup UID mismatch; resource was replaced")
        if row["item"]["kind"] == "PersistentVolumeClaim" and not row.get("pv"):
            volume = current.get("spec", {}).get("volumeName")
            if volume:
                _, pv = self.kube.call("GET", "/api/v1/persistentvolumes/" + volume)
                need(pv["spec"]["claimRef"]["uid"] == row["uid"] and pv["spec"].get("persistentVolumeReclaimPolicy") == "Delete", "unexpected backing PV during cleanup")
                row["pv"] = {"name": volume, "uid": pv["metadata"]["uid"]}
                self.save()
        self.kube.call("DELETE", row["path"], {"apiVersion": "v1", "kind": "DeleteOptions",
            "preconditions": {"uid": row["uid"]}, "propagationPolicy": "Foreground"}, expected=(200, 202, 404))
        # A VM's ordinary guest termination and foreground controller cleanup
        # can exceed two minutes. Wait within a fixed five-minute bound; do not
        # override grace periods, remove finalizers, or force-delete its Pod.
        timeout = 300 if row["item"]["kind"] == "VirtualMachine" else 120
        self.wait_absent(row["path"], timeout=timeout)
        if row.get("pv"):
            # The checked Delete reclaim policy must remove this exact owned
            # claim's PV as well. Never delete or change the provisioner.
            self.wait_absent("/api/v1/persistentvolumes/" + row["pv"]["name"])
        row["deleted"] = True
        self.save()

    def stop_forward(self):
        if self.forward:
            process, log = self.forward
            process.terminate()
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            log.close()
            self.forward = None

    def cleanup(self):
        self.stop_forward()
        failures = []
        for kind in ("NetworkPolicy", "VirtualMachine", "Pod", "Secret", "PersistentVolumeClaim"):
            for row in self.state["resources"]:
                if row["item"]["kind"] == kind:
                    try:
                        self.remove(row)
                    except Exception as error:
                        failures.append(str(error))
        self.state["cleanup_verified"] = not failures
        self.event("cleanup", complete=not failures, errors=failures)
        need(not failures, "cleanup incomplete; retain journal and run cleanup again")

    def health(self, capture=False):
        _, nodes = self.kube.call("GET", "/api/v1/nodes")
        observed = {}
        for node in nodes["items"]:
            name, status = node["metadata"]["name"], node["status"]
            conditions = {c["type"]: c["status"] for c in status.get("conditions", [])}
            if name in self.args.nodes:
                need(conditions.get("Ready") == "True" and not node.get("spec", {}).get("unschedulable"), "test worker not ready")
                need(conditions.get("CloudQualified") == "True", "test worker is not currently qualified")
                need(all(conditions.get(c) == "False" for c in ("MemoryPressure", "DiskPressure", "PIDPressure")), "test worker has resource pressure")
                platform = getattr(self.args, "platforms", {}).get(name, getattr(self.args, "platform", "snp"))
                need(platform in ("snp", "tdx"), "unknown hardware platform")
                tee = "sev-snp" if platform == "snp" else "tdx"
                label = "confidential.ai/sev-snp" if platform == "snp" else "kubevirt.io/tdx"
                need(node["metadata"].get("labels", {}).get(label) == "true", "test worker TEE label mismatch")
                if platform == "tdx":
                    _, host = self.kube.call("GET", "/apis/cloud.confidential.ai/v1alpha1/hosts/" + name)
                    hs = host.get("status", {})
                    need(hs.get("tee") == tee and hs.get("nodeUID") == node["metadata"]["uid"] and
                         hs.get("schedulable") is True and not hs.get("shuttingDown"), "Cloud Host did not qualify the requested TEE and Node UID")
                need(not any(k.startswith("node-role.kubernetes.io/control-plane") or k.startswith("node-role.kubernetes.io/etcd") for k in node["metadata"].get("labels", {})), "control-plane placement refused")
            observed[name] = {"uid": node["metadata"]["uid"], "boot_id": status["nodeInfo"]["bootID"], "conditions": conditions}
        _, live = self.kube.call("GET", "/apis/kubevirt.io/v1/virtualmachineinstances")
        vmis = {v["metadata"]["uid"]: {"namespace": v["metadata"]["namespace"], "name": v["metadata"]["name"],
            "vm_owner": next(({"name": o["name"], "uid": o["uid"]} for o in v["metadata"].get("ownerReferences", [])
                              if o.get("kind") == "VirtualMachine" and o.get("controller") is True and
                              o.get("apiVersion", "").startswith("kubevirt.io/")), None),
            "phase": v.get("status", {}).get("phase"), "ready": any(c["type"] == "Ready" and c["status"] == "True" for c in v.get("status", {}).get("conditions", []))}
            for v in live["items"]}
        if capture:
            self.state["nodes_before"] = observed
            self.state["vmis_before"] = vmis
            self.save()
        else:
            for name, before in self.state["nodes_before"].items():
                need(name in observed and observed[name]["uid"] == before["uid"] and observed[name]["boot_id"] == before["boot_id"], "Node identity/boot changed during test")
                if before["conditions"].get("Ready") == "True":
                    need(observed[name]["conditions"].get("Ready") == "True", "Node readiness regressed")
            for uid, before in self.state["vmis_before"].items():
                if uid in vmis and (not before["ready"] or vmis[uid]["ready"]):
                    continue
                # A declared stop/deletion of the owning VM is an external
                # lifecycle change, not evidence of an unexpected crash.
                # Never infer this from a VMI/Pod disappearing, its name, or
                # a workload label. A surviving owner without explicit intent
                # still fails closed; so does an unknown/replaced owner.
                owner = before.get("vm_owner")
                need(owner is not None, "existing VMI disappeared or readiness regressed; owner unknown")
                code, current = self.kube.call("GET", "/apis/kubevirt.io/v1/namespaces/" + before["namespace"] +
                    "/virtualmachines/" + owner["name"], expected=(200, 404))
                same_owner = code == 200 and current["metadata"]["uid"] == owner["uid"]
                deleting = code == 404 or (same_owner and bool(current["metadata"].get("deletionTimestamp")))
                halted = same_owner and current.get("spec", {}).get("runStrategy") == "Halted"
                need(deleting or halted,
                     "existing VMI disappeared or readiness regressed without explicit owning VM stop/deletion")
                change = "deletion" if deleting else "stop"
                changes = self.state.setdefault("external_vm_" + change + "s", {})
                if uid not in changes:
                    changes[uid] = {"namespace": before["namespace"], "vmi_name": before["name"],
                                    "owner": owner, "owner_http_status": code}
                    if halted and not deleting:
                        changes[uid]["run_strategy"] = "Halted"
                    self.event("external-vm-" + change + "-observed", vmi_uid=uid, **changes[uid])
        return observed

    def boot(self, vm, phase):
        row = self.create(vm)
        _, current = self.kube.call("GET", row["path"])
        need(current["metadata"]["uid"] == row["uid"], "VM replaced before start")
        self.command(phase + "-start", [self.args.virtctl, "--kubeconfig", self.args.kubeconfig, "-n", NS, "start", vm["metadata"]["name"]])
        _, started = self.kube.call("GET", row["path"])
        need(started["metadata"]["uid"] == row["uid"] and started["spec"].get("runStrategy") == "Manual", "start changed VM identity or manual lifetime policy")
        path = VMI + "/" + vm["metadata"]["name"]
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            code, vmi = self.kube.call("GET", path, expected=(200, 404))
            if code == 200 and any(x["type"] == "Ready" and x["status"] == "True" for x in vmi.get("status", {}).get("conditions", [])):
                need(any(o["uid"] == row["uid"] for o in vmi["metadata"].get("ownerReferences", [])), "VMI has unexpected owner")
                need(vmi["status"].get("nodeName") == vm["spec"]["template"]["spec"]["nodeSelector"]["kubernetes.io/hostname"], "wrong worker placement")
                self.event("vm-ready", phase=phase, vmi_uid=vmi["metadata"]["uid"], vm_uid=row["uid"], node=vmi["status"]["nodeName"])
                return row, vmi["metadata"]["uid"]
            time.sleep(3)
        raise RuntimeError("owned VMI readiness timed out")

    def probe(self, vm, phase, operation, expected, measurement):
        name = vm["metadata"]["name"]
        with socket.socket() as temporary:
            temporary.bind(("127.0.0.1", 0))
            port = temporary.getsockname()[1]
        def start_forward():
            log = (self.directory / (phase + "-forward.log")).open("ab")
            process = subprocess.Popen([self.args.virtctl, "--kubeconfig", self.args.kubeconfig, "-n", NS,
                "port-forward", "vmi/" + name, str(port) + ":6443"], stdout=log, stderr=subprocess.STDOUT)
            self.forward = process, log
            return process

        process = start_forward()
        # VM Ready is not guest service readiness. Only retry failed connects;
        # a sent seal with a lost response is safe (disposable independent keys).
        command = [self.args.probe, "request", "-operation", operation, "-expect", expected,
            "-product-line", self.args.product_line,
            "-url", f"http://127.0.0.1:{port}/v1/probe",
            "-measurement", measurement, "-launch-file", str(self.directory / "launch.json"),
            "-capsule-file", str(self.directory / "sentinel.json")]
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            try:
                need(process.poll() is None, "VM port-forward exited")
                body = self.command(phase, command, timeout=min(80, max(1, deadline - time.monotonic())))
                receipt = json.loads(body)
                self.atomic(self.directory / (phase + ".json"), receipt)
                return receipt
            except (RuntimeError, subprocess.TimeoutExpired):
                error_log = self.directory / (phase + ".stderr")
                if error_log.exists() and b"verified unexpected outcome" in error_log.read_bytes():
                    raise
                need(not (operation == "seal" and (self.directory / "sentinel.json").exists()), "seal saved capsule but receipt failed; retain evidence")
                # virtctl can leave its process/listening socket alive after
                # the first failed guest dial has ended its accept loop.
                # Recreate the owned tunnel, retaining its complete log.
                self.stop_forward()
                process = start_forward()
                self.event("vm-tunnel-restarted", phase=phase)
                time.sleep(3)
        raise RuntimeError("verified probe response timed out")

    def capture_boot_diagnostics(self):
        for row in self.state["resources"]:
            if row["item"]["kind"] != "VirtualMachine" or row.get("deleted") or not row.get("uid"):
                continue
            name = row["item"]["metadata"]["name"]
            code, vmi = self.kube.call("GET", VMI + "/" + name, expected=(200, 404))
            if code != 200 or not any(o["uid"] == row["uid"] for o in vmi["metadata"].get("ownerReferences", [])):
                continue
            self.atomic(self.directory / (name + "-failed-vmi.json"), vmi)
            _, pods = self.kube.call("GET", f"/api/v1/namespaces/{NS}/pods")
            for pod in pods["items"]:
                if not any(o["uid"] == vmi["metadata"]["uid"] for o in pod["metadata"].get("ownerReferences", [])):
                    continue
                self.command(name + "-guest-console", self.kubectl("logs", pod["metadata"]["name"],
                    "-c", "guest-console-log", "--tail=300"), timeout=20)
            # No cursor/keyboard input, guest agent, shell, or memory access.
            self.command(name + "-screenshot", [self.args.virtctl, "--kubeconfig", self.args.kubeconfig,
                "-n", NS, "vnc", "screenshot", name, "-f", str(self.directory / (name + "-screen.png"))], timeout=20)

    def exercise(self):
        measurement, hashes = image_inputs(self.args.image)
        need(not self.state["resources"], "existing journal: run cleanup, then choose a new directory")
        self.state["artifact_hashes"], self.state["measurement"] = hashes, measurement
        self.state["expected_product_line"] = self.args.product_line
        self.state["tool_hashes"] = {"probe": digest(self.args.probe), "renderer": digest(self.args.renderer), "runner": digest(__file__)}
        _, storage = self.kube.call("GET", "/apis/storage.k8s.io/v1/storageclasses/local-path")
        need(storage.get("reclaimPolicy") == "Delete" and storage.get("volumeBindingMode") == "WaitForFirstConsumer", "owned disk cleanup/placement contract unavailable")
        baseline = self.health(capture=True)
        need(len(self.args.nodes) == 2 and len(set(self.args.nodes)) == 2 and all(n in baseline for n in self.args.nodes), "two distinct SNP workers required")
        self.directory.joinpath("launch.json").write_text(json.dumps({"purpose":"cds-snp-disposable-v1","run":secrets.token_hex(16)}) + "\n")
        # Archives contain only locally verified, fixed-basename public files.
        for archive, files in (("root.tar.gz", [("disk.raw", "disk.img")]),
                               ("boot.tar.gz", [("guest-smp2.igvm", "guest-smp2.igvm"), ("manifest.json", "manifest.json")])):
            with tarfile.open(self.directory / archive, "w:gz", compresslevel=1) as tar:
                for src, dst in files:
                    tar.add(Path(self.args.image) / src, arcname=dst, recursive=False)
        receipts, vmis = [], []
        for index, node in enumerate(self.args.nodes):
            run = "cds-snp-" + secrets.token_hex(6)
            expiry = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=45)).replace(microsecond=0).isoformat()
            rendered = self.command(run + "-render", [self.args.renderer, "--run", run, "--node", node,
                "--node-uid", baseline[node]["uid"], "--launch-file", str(self.directory / "launch.json"),
                "--expires", expiry, "--tools-image", self.args.tools_image])
            items = json.loads(rendered)["items"]
            need(len(items) == 6, "unexpected fixture resource count")
            policy = next(i for i in items if i["kind"] == "NetworkPolicy")
            check_probe_network_policy(policy, run)
            for item in items:
                resource_path(item)
                self.kube.call("POST", resource_path(item).rsplit("/", 1)[0] + "?dryRun=All", item, expected=(201,))
            vm = next(i for i in items if i["kind"] == "VirtualMachine")
            need(all(vm["spec"]["template"]["metadata"]["labels"].get(k) == v
                     for k, v in policy["spec"]["podSelector"]["matchLabels"].items()),
                 "probe network policy does not select the owned VM")
            need(vm["spec"]["runStrategy"] == "Manual", "VM must require explicit starts and stay off after expiry")
            for item in items:
                if item["kind"] != "VirtualMachine":
                    self.create(item)
            pop = next(r for r in self.state["resources"] if r["item"]["metadata"]["name"] == run + "-populate")
            self.command(run + "-population-ready", self.kubectl("wait", "--for=condition=Ready", "pod/" + run + "-populate", "--timeout=180s"), timeout=190)
            for row in self.state["resources"]:
                if row["item"]["kind"] != "PersistentVolumeClaim" or row.get("deleted"):
                    continue
                _, claim = self.kube.call("GET", row["path"])
                need(claim["metadata"]["uid"] == row["uid"], "owned claim replaced")
                _, pv = self.kube.call("GET", "/api/v1/persistentvolumes/" + claim["spec"]["volumeName"])
                need(pv["spec"]["claimRef"]["uid"] == row["uid"] and pv["spec"].get("persistentVolumeReclaimPolicy") == "Delete", "unexpected backing PV")
                row["pv"] = {"name": pv["metadata"]["name"], "uid": pv["metadata"]["uid"]}
                self.save()
            for archive, destination in (("root.tar.gz", "/rootdisk"), ("boot.tar.gz", "/bootfiles")):
                self.upload(run + "-populate", archive, destination)
            sums = self.command(run + "-hashes", self.kubectl("exec", run + "-populate", "--", "sha256sum", "/rootdisk/disk.img", "/bootfiles/guest-smp2.igvm")).decode().splitlines()
            need(sums == [hashes["disk.raw"] + "  /rootdisk/disk.img", hashes["guest-smp2.igvm"] + "  /bootfiles/guest-smp2.igvm"], "uploaded artifact digest mismatch")
            self.remove(pop)
            phases = [("seal", "seal", "sealed"), ("same-chip", "open", "opened")] if index == 0 else [("other-chip", "open", "rejected")]
            for phase, operation, expected in phases:
                self.health()
                row, vmi = self.boot(vm, phase)
                need(vmi not in vmis, "VMI identity reused")
                vmis.append(vmi)
                receipt = self.probe(vm, phase, operation, expected, measurement)
                receipts.append(receipt)
                self.stop_forward()
                if phase == "seal":
                    control = self.probe(vm, "live-control", "open", "opened", measurement)
                    self.stop_forward()
                    need(control["guest_report_id_sha256"] == receipt["guest_report_id_sha256"] and
                         control["chip_sha256"] == receipt["chip_sha256"] and
                         control["reply"]["result"]["capsule"] == receipt["reply"]["result"]["capsule"] and
                         control["request"]["nonce"] != receipt["request"]["nonce"], "live-guest identity control failed")
                    self.state["live_guest_control_passed"] = True
                    self.save()
                self.remove(row)
                self.wait_absent(VMI + "/" + run)
            self.cleanup()  # no concurrent guests; remove first worker's disks
        need(receipts[0]["chip_sha256"] == receipts[1]["chip_sha256"] != receipts[2]["chip_sha256"], "chip placement did not establish same/different-chip cases")
        need(receipts[0]["reply"]["result"]["capsule"] == receipts[1]["reply"]["result"]["capsule"], "recovered capsule changed")
        need(all(r["request"]["capsule"] == receipts[0]["reply"]["result"]["capsule"] for r in receipts[1:]), "recovery/rejection used a different capsule")
        need(len({r["request"]["nonce"] for r in receipts}) == 3, "request nonce reused")
        need(len({r["guest_report_id_sha256"] for r in receipts}) == 3, "hardware guest identity reused; recreation not established")
        self.health()
        self.state["hardware_primitive_passed"] = True
        self.event("primitive-passed", full_acceptance_passed=False, production_ready=False)


def interrupt_run(signum, frame):
    # InterruptedError is an OSError: subprocess waitpid may swallow it as an
    # interrupted system call. SystemExit escapes to our cleanup finally and
    # makes subprocess reap the child rather than defer KeyboardInterrupt cleanup.
    raise SystemExit("test interrupted")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["run", "cleanup"])
    for field in ("directory", "cloud-repo", "kubeconfig", "kubectl", "virtctl"):
        parser.add_argument("--" + field, required=True)
    for field in ("image", "renderer", "probe", "tools-image"):
        parser.add_argument("--" + field)
    parser.add_argument("--nodes", nargs=2)
    parser.add_argument("--product-line", choices=["Milan", "Genoa", "Turin"])
    args = parser.parse_args()
    os.umask(0o077)
    Path(args.directory).mkdir(parents=True, exist_ok=True)
    sys.path.insert(0, str(Path(args.cloud_repo) / "integration/production"))
    from cds_ha_rehearsal import kube_client, atomic_json
    run = Run(args, kube_client(args.kubeconfig), atomic_json)
    if args.action == "cleanup":
        need(run.path.exists(), "cleanup requires an existing ownership journal")
        run.cleanup()
        return
    need(all(getattr(args, f) for f in ("image", "renderer", "probe", "tools_image", "nodes", "product_line")), "run requires complete measured inputs and expected AMD product line")
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, interrupt_run)
    signal.signal(signal.SIGALRM, lambda signum, frame: (_ for _ in ()).throw(TimeoutError("45-minute test deadline")))
    signal.alarm(2700)
    try:
        run.exercise()
    except BaseException as error:
        run.event("failed", reason=str(error))
        try:
            run.capture_boot_diagnostics()
        except Exception as diagnostic_error:
            run.event("diagnostics-unavailable", reason=str(diagnostic_error))
        raise
    finally:
        signal.alarm(0)
        try:
            run.cleanup()
        finally:
            if "nodes_before" in run.state:
                try:
                    run.health()
                    run.event("post-cleanup-observations", unchanged=not bool(run.state.get("external_vm_deletions") or run.state.get("external_vm_stops")),
                              unexpected_regression_detected=False)
                except Exception as error:
                    run.event("post-cleanup-observations", unchanged=False, unexpected_regression_detected=True, reason=str(error))
                    raise


if __name__ == "__main__":
    main()
