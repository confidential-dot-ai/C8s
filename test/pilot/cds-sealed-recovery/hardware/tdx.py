#!/usr/bin/env python3
"""Disposable TDX attestation/capability qualification using the owned lifecycle.

No host module/firmware changes, key requests, secrets or CDS recovery claims.
The common runner supplies creation reconciliation, health checks and UID cleanup.
"""
import argparse
import base64
import datetime as dt
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
import urllib.error
import urllib.request

from run import Run, NS, LABEL, VMI, need, digest, resource_path, check_probe_network_policy, interrupt_run


def image_inputs(directory):
    p = Path(directory)
    m = json.loads((p / "manifest.json").read_text())
    need(m["version"] == 3 and m["build"]["platform"] == "tdx" and m["build"]["memory"] == "4G", "TDX 4G manifest v3 required")
    pins = m["tdx"]
    need(all(re.fullmatch(r"[0-9a-f]{96}", pins[k]) and set(pins[k]) != {"0"} for k in ("mrtd", "rtmr1", "rtmr2")), "complete independent TDX image pins required")
    entries = [(m["outputs"]["disk_image"], "disk.raw"), (m["outputs"]["uki"], "uki.efi"), (pins["firmware"], "OVMF.tdx.fd")]
    for entry, name in entries:
        need(entry["path"] == name and digest(p / name) == entry["sha256"], "artifact hash mismatch: " + name)
    need((p / "disk.raw").stat().st_size < 8*1024**3, "root disk exceeds owned claim")
    return pins, {name: e["sha256"] for e, name in entries}


def check_fixture(items, run, node, uid):
    need(len(items) == 5 and sorted(i["kind"] for i in items) == ["NetworkPolicy", "PersistentVolumeClaim", "Pod", "Secret", "VirtualMachine"], "unexpected TDX fixture resources")
    for item in items:
        resource_path(item)
        need(item["metadata"]["labels"][LABEL] == run, "mixed fixture ownership")
    vm = next(i for i in items if i["kind"] == "VirtualMachine")
    spec = vm["spec"]["template"]["spec"]
    selector = spec["nodeSelector"]
    need(selector.get("kubernetes.io/hostname") == node and selector.get("cloud.confidential.ai.node-restriction.kubernetes.io/node-uid") == uid, "worker identity must be pinned")
    need(vm["spec"]["runStrategy"] == "Manual" and spec["domain"].get("launchSecurity") == {"tdx": {}}, "manual native TDX guest required")
    need(not any("cloudInit" in json.dumps(v) for v in spec.get("volumes", [])), "cloud-init is forbidden")
    policy = next(i for i in items if i["kind"] == "NetworkPolicy")
    check_probe_network_policy(policy, run)
    need(all(vm["spec"]["template"]["metadata"]["labels"].get(k) == v for k, v in policy["spec"]["podSelector"]["matchLabels"].items()), "network policy does not select the owned guest")
    return vm


class TDXRun(Run):
    def native_probe(self, vm):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        url = f"http://127.0.0.1:{port}"
        deadline = time.monotonic() + 180
        # Guest networking can lag VMI Ready; recreate only our tunnel if its
        # first guest dial failed. A successful health read precedes any probe.
        while time.monotonic() < deadline:
            self.stop_forward()
            log = (self.directory / "probe-forward.log").open("ab")
            process = subprocess.Popen([self.args.virtctl, "--kubeconfig", self.args.kubeconfig, "-n", NS,
                "port-forward", "vmi/"+vm["metadata"]["name"], f"{port}:6443"], stdout=log, stderr=subprocess.STDOUT)
            self.forward = process, log
            for _ in range(4):
                time.sleep(2)
                try:
                    with urllib.request.urlopen(url+"/health", timeout=5) as r:
                        need(r.status == 204, "unexpected probe health response")
                    break
                except (urllib.error.URLError, TimeoutError):
                    continue
            else:
                continue
            break
        else:
            raise RuntimeError("native guest probe readiness timed out")
        for index in range(2):
            phase = f"native-{index}"
            q = {"nonce": base64.b64encode(secrets.token_bytes(32)).decode()}
            self.atomic(self.directory / (phase+"-request.json"), q)
            req = urllib.request.Request(url+"/v1/probe", data=json.dumps(q).encode(), headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=45) as response:
                b = response.read(128*1024+1)
            need(len(b) <= 128*1024, "oversized native reply")
            (self.directory / (phase+"-reply.json")).write_bytes(b)
            self.command(phase+"-verify", [self.args.probe, "-mode", "verify", "-request", str(self.directory/(phase+"-request.json")),
                "-reply", str(self.directory/(phase+"-reply.json")), "-launch", str(self.directory/"launch.json"),
                "-manifest", str(Path(self.args.image)/"manifest.json"), "-receipt", str(self.directory/(phase+"-receipt.json")),
                "-collateral", str(self.directory/(phase+"-collateral.json"))], timeout=90)
            receipt = json.loads((self.directory/(phase+"-receipt.json")).read_text())
            need(receipt["attestation_chain_verified"] and receipt["image_pins_verified"] and receipt["launch_binding_verified"], "incomplete native verification")
            self.event("native-quote-verified", phase=phase, feature_query_succeeded=receipt["feature_query_succeeded"],
                native_sealing_advertised=receipt["native_sealing_advertised"], status=receipt["result"]["status"], features=receipt["result"]["features"])
        # A negative control must fail specifically on the nonce commitment;
        # collateral/network failure cannot count as replay protection.
        stale = subprocess.run([self.args.probe, "-mode", "verify", "-request", str(self.directory/"native-1-request.json"),
            "-reply", str(self.directory/"native-0-reply.json"), "-launch", str(self.directory/"launch.json"),
            "-manifest", str(Path(self.args.image)/"manifest.json"), "-receipt", str(self.directory/"stale-receipt.json"),
            "-collateral", str(self.directory/"stale-collateral.json")], capture_output=True, timeout=90)
        (self.directory/"stale-quote.stderr").write_bytes(stale.stderr)
        need(stale.returncode != 0 and b"REPORT_DATA" in stale.stderr and not (self.directory/"stale-receipt.json").exists(),
             "stale quote did not fail specifically on its nonce commitment")
        self.event("stale-native-quote-rejected", reason="REPORT_DATA mismatch")
        self.state["tdx_attestation_qualified"] = True
        self.state["tdx_capability_query_succeeded"] = receipt["feature_query_succeeded"]
        self.state["tdx_native_sealing_advertised"] = receipt["native_sealing_advertised"]
        self.state["tdx_native_sealing_qualified"] = False
        self.save()

    def exercise(self):
        pins, hashes = image_inputs(self.args.image)
        need(not self.state["resources"], "existing journal: clean up, then choose a new directory")
        self.state.update(platform="tdx", image_pins=pins, artifact_hashes=hashes,
            tool_hashes={"probe": digest(self.args.probe), "renderer": digest(self.args.renderer), "runner": digest(__file__)})
        _, storage = self.kube.call("GET", "/apis/storage.k8s.io/v1/storageclasses/local-path")
        need(storage.get("reclaimPolicy") == "Delete" and storage.get("volumeBindingMode") == "WaitForFirstConsumer", "owned disk cleanup/placement unavailable")
        baseline = self.health(capture=True)
        need(len(self.args.nodes) == 1 and self.args.nodes[0] in baseline, "one qualified TDX compute worker required")
        node = self.args.nodes[0]
        self.directory.joinpath("launch.json").write_text(json.dumps({"purpose": "cds-tdx-capability-v1", "run": secrets.token_hex(16)})+"\n")
        with tarfile.open(self.directory/"root.tar.gz", "w:gz", compresslevel=1) as tar:
            tar.add(Path(self.args.image)/"disk.raw", arcname="disk.img", recursive=False)
        run = "cds-tdx-"+secrets.token_hex(6)
        expiry = (dt.datetime.now(dt.timezone.utc)+dt.timedelta(minutes=30)).replace(microsecond=0).isoformat()
        rendered = self.command(run+"-render", [self.args.renderer, "--platform", "tdx", "--run", run, "--node", node,
            "--node-uid", baseline[node]["uid"], "--launch-file", str(self.directory/"launch.json"),
            "--expires", expiry, "--tools-image", self.args.tools_image])
        items = json.loads(rendered)["items"]
        vm = check_fixture(items, run, node, baseline[node]["uid"])
        for item in items:
            self.kube.call("POST", resource_path(item).rsplit("/", 1)[0]+"?dryRun=All", item, expected=(201,))
        for item in items:
            if item["kind"] != "VirtualMachine": self.create(item)
        pop = next(r for r in self.state["resources"] if r["item"]["kind"] == "Pod")
        pod = pop["item"]["metadata"]["name"]
        self.command("population-ready", self.kubectl("wait", "--for=condition=Ready", "pod/"+pod, "--timeout=180s"), timeout=190)
        self.upload(pod, "root.tar.gz", "/rootdisk")
        remote = self.command("disk-hash", self.kubectl("exec", pod, "--", "sha256sum", "/rootdisk/disk.img"))
        need(remote.split()[0].decode() == hashes["disk.raw"], "uploaded root disk hash mismatch")
        self.remove(pop)
        row, uid = self.boot(vm, "tdx-capability")
        self.native_probe(vm)
        self.stop_forward()
        self.remove(row)
        self.wait_absent(VMI+"/"+run)
        self.event("native-probe-completed", vmi_uid=uid, native_sealing_qualified=False)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=["run", "cleanup"])
    for field in ("directory", "cloud-repo", "kubeconfig", "kubectl", "virtctl"): p.add_argument("--"+field, required=True)
    for field in ("image", "renderer", "probe", "tools-image"): p.add_argument("--"+field)
    p.add_argument("--nodes", nargs=1)
    args = p.parse_args()
    args.platform = "tdx"
    os.umask(0o077)
    Path(args.directory).mkdir(parents=True, exist_ok=True)
    sys.path.insert(0, str(Path(args.cloud_repo)/"integration/production"))
    from cds_ha_rehearsal import kube_client, atomic_json
    run = TDXRun(args, kube_client(args.kubeconfig), atomic_json)
    if args.action == "cleanup":
        need(run.path.exists(), "cleanup requires existing ownership journal")
        run.cleanup()
        return
    need(all(getattr(args, f) for f in ("image", "renderer", "probe", "tools_image", "nodes")), "complete independent probe inputs required")
    for sig in (signal.SIGINT, signal.SIGTERM): signal.signal(sig, interrupt_run)
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError("30-minute qualification deadline")))
    signal.alarm(1800)
    try:
        run.exercise()
    except BaseException as error:
        run.event("failed", reason=str(error))
        try: run.capture_boot_diagnostics()
        except Exception as e: run.event("diagnostics-unavailable", reason=str(e))
        raise
    finally:
        signal.alarm(0)
        try: run.cleanup()
        finally:
            if "nodes_before" in run.state:
                run.health()
                run.event("post-cleanup-observations", unexpected_regression_detected=False)


if __name__ == "__main__": main()
