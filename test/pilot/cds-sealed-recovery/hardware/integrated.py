#!/usr/bin/env python3
"""Owned SNP CDS recovery test; no shared rollout, egress grant, or CI.

Three CDS processes and their custodian live in one disposable measured VM.
The host owns a bounded conditional-object fixture whose SQLite FULL commits
finish before acknowledging S3 writes. Only ciphertext/public metadata cross
the VM tunnel. This is a correctness test, not an S3 latency benchmark.
"""
import argparse
import base64
import datetime as dt
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import sqlite3
import subprocess
import sys
import tarfile
import threading
import time

from run import Run, NS, VMI, LABEL, need, digest, image_inputs, resource_path, check_probe_network_policy, interrupt_run


class DurableObjects:
    """One worker owns the connection; no lock or mutable global store."""
    def __init__(self, path, prefix):
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("CREATE TABLE IF NOT EXISTS objects (path TEXT PRIMARY KEY, body BLOB NOT NULL, version INTEGER NOT NULL)")
        self.db.execute("CREATE TABLE IF NOT EXISTS sequence (id INTEGER PRIMARY KEY CHECK(id=1), value INTEGER NOT NULL)")
        self.db.execute("INSERT OR IGNORE INTO sequence VALUES(1,0)")
        self.db.commit()
        self.prefix = "/pilot/" + prefix + "/"
        self.reads = self.writes = self.conflicts = 0

    def answer(self, request):
        need(request["path"].startswith(self.prefix) and ".." not in request["path"], "storage path outside owned prefix")
        response = {"id": request["id"], "status": 200}
        path = request["path"]
        old = self.db.execute("SELECT body,version FROM objects WHERE path=?", (path,)).fetchone()
        if request["method"] == "GET":
            self.reads += 1
            if old is None:
                response.update(status=404, data=base64.b64encode(b"<Error><Code>NoSuchKey</Code></Error>").decode())
            else:
                response.update(etag=f'"{old[1]}"', data=base64.b64encode(old[0]).decode())
        elif request["method"] == "PUT":
            body = base64.b64decode(request.get("data", ""), validate=True)
            need(len(body) <= 8 * 1024**2, "object exceeds fixture bound")
            absent, match = request.get("absent", ""), request.get("match", "")
            need((absent == "*") != bool(match), "exactly one conditional-write predicate required")
            if (absent and old is not None) or (match and (old is None or match != f'"{old[1]}"')):
                self.conflicts += 1
                response.update(status=412, data=base64.b64encode(b"<Error><Code>PreconditionFailed</Code></Error>").decode())
            else:
                with self.db:
                    self.db.execute("UPDATE sequence SET value=value+1 WHERE id=1")
                    version = self.db.execute("SELECT value FROM sequence WHERE id=1").fetchone()[0]
                    self.db.execute("INSERT INTO objects VALUES(?,?,?) ON CONFLICT(path) DO UPDATE SET body=excluded.body, version=excluded.version", (path, body, version))
                # FULL synchronous commit above is the acknowledgment boundary.
                self.writes += 1
                response["etag"] = f'"{version}"'
        else:
            raise RuntimeError("unsupported storage operation")
        return response

    def close(self):
        self.db.close()


class Integrated(Run):
    def upload(self, pod, archive, destination):
        # Bound each native exec upload below the streaming proxy's lifetime.
        # A lost response is reconciled by the exact chunk hash, never its exit
        # code. The final disk/IGVM hashes are still checked before any VM boots.
        transfer = secrets.token_hex(12)
        parts = []
        with (self.directory / archive).open("rb") as source:
            for index in range(1024):
                chunk = source.read(8 * 1024**2)
                if not chunk:
                    break
                remote = f"{destination}/.cds-{transfer}-{index:04d}"
                expected = hashlib.sha256(chunk).hexdigest() + "  " + remote
                for attempt in range(3):
                    try:
                        with (self.directory / f"{pod}-{archive}-{index:04d}.stderr").open("ab") as errors:
                            subprocess.run(self.kubectl("exec", "-i", pod, "--", "sh", "-c",
                                'head -c "$1" > "$2"', "chunk-receiver", str(len(chunk)), remote),
                                input=chunk, stdout=subprocess.DEVNULL, stderr=errors, timeout=45)
                    except subprocess.TimeoutExpired:
                        pass
                    try:
                        actual = self.command(f"{pod}-{archive}-{index:04d}-hash", self.kubectl("exec", pod, "--", "sha256sum", remote), timeout=20).decode().strip()
                    except (RuntimeError, subprocess.TimeoutExpired):
                        actual = ""
                    if actual == expected:
                        break
                else:
                    raise RuntimeError("public artifact chunk could not be verified")
                parts.append(remote)
                self.event("upload-chunk-verified", archive=archive, chunk=index, bytes=len(chunk))
            else:
                raise RuntimeError("artifact exceeds transfer bound")
        need(parts, "empty artifact archive")
        marker = destination + "/.cds-upload-complete"
        token = secrets.token_hex(16)
        argv = self.kubectl("exec", pod, "--", "sh", "-c",
            'destination=$1; token=$2; shift 2; cat "$@" | tar --checkpoint=1024 --checkpoint-action=echo -xz -C "$destination" && '
            'printf "%s" "$token" > "$destination/.cds-upload-complete"',
            "archive-extractor", destination, token, *parts)
        with (self.directory / f"{pod}-{archive}-extract.log").open("wb") as log:
            process = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 300
                while time.monotonic() < deadline:
                    try:
                        value = self.command(f"{pod}-{archive}-completion", self.kubectl("exec", pod, "--", "sh", "-c", 'if [ -f "$1" ]; then cat "$1"; fi', "completion", marker), timeout=20)
                    except (RuntimeError, subprocess.TimeoutExpired):
                        value = b""
                    if value == token.encode():
                        self.event("upload-receiver-completed", archive=archive, chunks=len(parts))
                        return
                    need(not value, "unexpected extraction completion token")
                    time.sleep(3)
                raise TimeoutError("verified-chunk extraction did not complete")
            finally:
                if process.poll() is None:
                    process.terminate()
                    try: process.wait(timeout=5)
                    except subprocess.TimeoutExpired: process.kill(); process.wait()

    def http(self, port, method, path, value=None, timeout=25):
        # Only an authenticated native VM tunnel on loopback; never use a proxy.
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
        try:
            c.request(method, path, None if value is None else json.dumps(value), {"Content-Type": "application/json"})
            r = c.getresponse()
            body = r.read(32 * 1024**2 + 1)
            need(len(body) <= 32 * 1024**2, "oversized relay response")
            return r.status, json.loads(body) if body and r.status in (200, 202) else None
        finally:
            c.close()

    def tunnel(self, vm, phase):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            log = (self.directory / (phase + "-forward.log")).open("ab")
            p = subprocess.Popen([self.args.virtctl, "--kubeconfig", self.args.kubeconfig, "-n", NS, "port-forward", "vmi/" + vm["metadata"]["name"], f"{port}:6443"], stdout=log, stderr=subprocess.STDOUT)
            self.forward = p, log
            try:
                time.sleep(1)
                if self.http(port, "GET", "/health", timeout=3)[0] == 204:
                    return port
            except (OSError, http.client.HTTPException):
                pass
            self.stop_forward()
            time.sleep(2)
        raise RuntimeError("measured guest service did not become reachable")

    def phase(self, vm, phase, launch, parameters, collateral):
        port = self.tunnel(vm, phase)
        request = {"operation": phase, "nonce": base64.b64encode(secrets.token_bytes(32)).decode(), "measurement": self.state["measurement"], "parameters": parameters}
        if phase != "enroll":
            request.update(collateral=collateral, operator_key=base64.b64encode((self.directory / "operator.pem").read_bytes()).decode())
        self.atomic(self.directory / (phase + "-request.json"), request)
        stop = threading.Event()
        failures = []
        counters = {}

        def serve_storage():
            store = DurableObjects(self.directory / "objects.sqlite", self.state["prefix"])
            try:
                while not stop.is_set():
                    code, q = self.http(port, "GET", "/v1/storage")
                    if code == 204:
                        continue
                    need(code == 200, "storage poll failed")
                    response = store.answer(q)
                    code, _ = self.http(port, "POST", "/v1/storage", response)
                    need(code in (204, 409), "storage response failed")
            except Exception as error:
                if not stop.is_set():
                    failures.append(str(error))
            finally:
                counters.update(reads=store.reads, writes=store.writes, conflicts=store.conflicts)
                store.close()

        worker = threading.Thread(target=serve_storage, daemon=True)
        worker.start()
        try:
            code, _ = self.http(port, "POST", "/v1/start", request)
            need(code == 202, "phase start refused or ambiguous")
            deadline = time.monotonic() + 480
            progress = time.monotonic()
            while time.monotonic() < deadline:
                need(not failures, "external durable store failed: " + str(failures))
                code, reply = self.http(port, "GET", "/v1/result")
                if code == 200:
                    self.atomic(self.directory / (phase + "-reply.json"), reply)
                    break
                need(code == 202, "phase status unavailable")
                if time.monotonic() - progress > 30:
                    self.event("cds-phase-running", phase=phase)
                    progress = time.monotonic()
                time.sleep(1)
            else:
                raise RuntimeError("CDS phase deadline exceeded")
        finally:
            stop.set()
            worker.join(timeout=27)
            need(not worker.is_alive(), "storage worker did not stop")
            self.event("external-storage", phase=phase, **counters)
        self.command(phase + "-verify", [self.args.probe, "-request", str(self.directory / (phase + "-request.json")), "-reply", str(self.directory / (phase + "-reply.json")), "-launch", str(launch), "-receipt", str(self.directory / (phase + "-receipt.json")), "-collateral", str(self.directory / (phase + "-collateral.json"))], timeout=60)
        receipt = json.loads((self.directory / (phase + "-receipt.json")).read_text())
        self.event("cds-phase-passed", phase=phase, checks=receipt["result"].get("checks", {}))
        return receipt

    def render(self, run, node, uid, launch):
        expiry = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=45)).replace(microsecond=0).isoformat()
        items = json.loads(self.command(run + "-render-" + launch.stem, [self.args.renderer, "--run", run, "--node", node, "--node-uid", uid, "--launch-file", str(launch), "--expires", expiry, "--tools-image", self.args.tools_image]))["items"]
        need(len(items) == 6, "unexpected fixture resource count")
        check_probe_network_policy(next(i for i in items if i["kind"] == "NetworkPolicy"), run)
        for item in items:
            path = resource_path(item)
            code, current = self.kube.call("GET", path, expected=(200, 404))
            if code == 404:
                self.kube.call("POST", path.rsplit("/", 1)[0] + "?dryRun=All", item, expected=(201,))
            else:
                owned = [r for r in self.state["resources"] if r["path"] == path and not r.get("deleted")]
                need(len(owned) == 1 and owned[0]["uid"] == current["metadata"]["uid"] and
                     current["metadata"].get("labels", {}).get(LABEL) == run,
                     "render found an unrelated existing resource")
        return items

    def populate(self, items, hashes, run):
        for item in items:
            if item["kind"] != "VirtualMachine": self.create(item)
        pop = next(r for r in self.state["resources"] if r["item"]["metadata"]["name"] == run + "-populate")
        self.command(run + "-population-ready", self.kubectl("wait", "--for=condition=Ready", "pod/" + run + "-populate", "--timeout=180s"), timeout=190)
        for row in self.state["resources"]:
            if row["item"]["kind"] == "PersistentVolumeClaim":
                _, claim = self.kube.call("GET", row["path"])
                need(claim["metadata"]["uid"] == row["uid"], "owned claim replaced")
                _, pv = self.kube.call("GET", "/api/v1/persistentvolumes/" + claim["spec"]["volumeName"])
                need(pv["spec"]["claimRef"]["uid"] == row["uid"] and pv["spec"].get("persistentVolumeReclaimPolicy") == "Delete", "unexpected backing PV")
                row["pv"] = {"name": pv["metadata"]["name"], "uid": pv["metadata"]["uid"]}
                self.save()
        for archive, destination in (("root.tar.gz", "/rootdisk"), ("boot.tar.gz", "/bootfiles")):
            self.upload(run + "-populate", archive, destination)
        sums = self.command(run + "-hashes", self.kubectl("exec", run + "-populate", "--", "sha256sum", "/rootdisk/disk.img", "/bootfiles/guest-smp2.igvm")).decode().splitlines()
        need(sums == [hashes["disk.raw"] + "  /rootdisk/disk.img", hashes["guest-smp2.igvm"] + "  /bootfiles/guest-smp2.igvm"], "uploaded artifact mismatch")
        self.remove(pop)

    def exercise(self):
        import yaml
        measurement, hashes = image_inputs(self.args.image)
        need(not self.state["resources"], "new run directory required")
        self.state.update(artifact_hashes=hashes, measurement=measurement, prefix="integrated-" + secrets.token_hex(12), expected_product_line="Genoa")
        self.state["tool_hashes"] = {"verifier": digest(self.args.probe), "renderer": digest(self.args.renderer), "runner": digest(__file__)}
        _, storage = self.kube.call("GET", "/apis/storage.k8s.io/v1/storageclasses/local-path")
        need(storage.get("reclaimPolicy") == "Delete" and storage.get("volumeBindingMode") == "WaitForFirstConsumer", "owned disk cleanup contract unavailable")
        baseline = self.health(capture=True)
        node = self.args.nodes[0]
        need(node in baseline, "approved SNP worker missing")
        self.command("operator-key", ["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(self.directory / "operator.pem")])
        public = self.command("operator-public", ["openssl", "ec", "-in", str(self.directory / "operator.pem"), "-pubout"]).decode()
        config = {"schemaVersion": "c8s-cds/v1", "clusterID": "lane", "operatorPublicKeys": public,
                  "workloads": json.dumps({"schema": "c8s.allowlist/v1", "workloads": {"attestation-api": {"containers": [{"digest": "sha256:" + "11" * 32, "command": {"policy": "any"}, "args": {"policy": "any"}}]}}}),
                  "nodes": json.dumps({"schema_version": "1", "tee": "sev-snp", "measurements": [{"name": "node", "measurement": measurement}]}),
                  "nodeCIDRs": ["10.0.2.0/24"], "leafDNSNames": ["workload.lane.svc"],
                  "ha": {"replicas": ["127.0.77.1", "127.0.77.2", "127.0.77.3"], "voters": 3,
                         "objectWALPilot": {"bucket": "pilot", "region": "us-east-2", "prefix": self.state["prefix"], "endpoint": "https://127.0.0.1:9443", "pathStyle": True, "recoveryAuthority": base64.b64encode(bytes([1]) * 32).decode()}}}
        template = self.directory / "enrollment-launch.yaml"
        template.write_text(yaml.safe_dump(config, sort_keys=True))
        for archive, files in (("root.tar.gz", [("disk.raw", "disk.img")]), ("boot.tar.gz", [("guest-smp2.igvm", "guest-smp2.igvm"), ("manifest.json", "manifest.json")])):
            with tarfile.open(self.directory / archive, "w:gz", compresslevel=1) as tar:
                for src, dst in files: tar.add(Path(self.args.image) / src, arcname=dst, recursive=False)
        run = "cds-snp-" + secrets.token_hex(6)
        items = self.render(run, node, baseline[node]["uid"], template)
        self.populate(items, hashes, run)
        vm = next(i for i in items if i["kind"] == "VirtualMachine")
        row, enrollment_vmi = self.boot(vm, "enroll")
        enrolled = self.phase(vm, "enroll", template, {"guest_svn": 0, "tcb_version": 0}, {})
        self.stop_forward(); self.remove(row); self.wait_absent(VMI + "/" + run)
        launch = self.directory / "cds-launch.yaml"
        launch.write_bytes(base64.b64decode(enrolled["result"]["launch"], validate=True))
        # Verify the attested enrollment changed exactly the authority public key.
        final = yaml.safe_load(launch.read_text())
        public_authority = final["ha"]["objectWALPilot"].pop("recoveryAuthority")
        original_authority = config["ha"]["objectWALPilot"].pop("recoveryAuthority")
        need(final == config and public_authority != original_authority, "enrollment changed unrelated launch settings")
        items = self.render(run, node, baseline[node]["uid"], launch)
        old_secret = next(r for r in self.state["resources"] if r["item"]["kind"] == "Secret" and not r.get("deleted"))
        self.remove(old_secret)
        self.create(next(i for i in items if i["kind"] == "Secret"))
        vm = next(i for i in items if i["kind"] == "VirtualMachine")
        parameters = enrolled["result"]["parameters"]
        collateral = json.loads((self.directory / "enroll-collateral.json").read_text())
        receipts, vmis = [], [enrollment_vmi]
        for phase in ("seed", "recover"):
            self.health()
            row, vmi = self.boot(vm, phase)
            need(vmi not in vmis, "new VMI required")
            vmis.append(vmi)
            receipts.append(self.phase(vm, phase, launch, parameters, collateral))
            self.stop_forward()
            self.remove(row)
            self.wait_absent(VMI + "/" + run)
            self.event("all-cds-and-custodian-memory-destroyed", phase=phase, vmi_uid=vmi)
        need(len({r["guest_report_id_sha256"] for r in [enrolled] + receipts}) == 3, "hardware guest identities must differ")
        need(len({r["chip_id_sha256"] for r in [enrolled] + receipts}) == 1, "same chip recovery required")
        before, after = [r["result"]["checks"] for r in receipts]
        need(before["ca_fingerprint"] == after["ca_fingerprint"], "independent CA receipts differ")
        need(all(after.get(k) is True for k in ("same_ca_all_replicas", "unexpired_replay_rejected_all_replicas", "revocation_preserved_all_replicas", "old_leaf_and_secret_positive_control")), "acceptance evidence incomplete")
        self.state["integrated_cds_recovery_passed"] = True
        self.state["full_acceptance_passed"] = False  # fleet/image retirement/operator-policy proof remain separate
        self.event("integrated-cds-recovery-passed", ca_fingerprint=after["ca_fingerprint"], production_ready=False)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=["run", "cleanup"])
    for field in ("directory", "cloud-repo", "kubeconfig", "kubectl", "virtctl"):
        p.add_argument("--" + field, required=True)
    for field in ("image", "renderer", "probe", "tools-image"):
        p.add_argument("--" + field)
    p.add_argument("--nodes", nargs="+", default=[])
    args = p.parse_args()
    os.umask(0o077)
    Path(args.directory).mkdir(parents=True, exist_ok=True)
    sys.path.insert(0, str(Path(args.cloud_repo) / "integration/production"))
    from cds_ha_rehearsal import kube_client, atomic_json
    run = Integrated(args, kube_client(args.kubeconfig), atomic_json)
    if args.action == "cleanup":
        need(run.path.exists(), "cleanup requires an ownership journal")
        run.cleanup(); return
    need(all(getattr(args, f) for f in ("image", "renderer", "probe", "tools_image", "nodes")), "all measured inputs required")
    for sig in (signal.SIGINT, signal.SIGTERM): signal.signal(sig, interrupt_run)
    signal.signal(signal.SIGALRM, lambda signum, frame: (_ for _ in ()).throw(TimeoutError("45-minute deadline")))
    signal.alarm(2700)
    try:
        run.exercise()
    except BaseException as error:
        run.event("failed", reason=str(error))
        try: run.capture_boot_diagnostics()
        except Exception as diagnostic: run.event("diagnostics-unavailable", reason=str(diagnostic))
        raise
    finally:
        signal.alarm(0)
        try: run.cleanup()
        finally:
            if "nodes_before" in run.state:
                run.health()
                run.event("post-cleanup-observations", unexpected_regression_detected=False)


if __name__ == "__main__": main()
