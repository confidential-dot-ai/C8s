#!/usr/bin/env python3
"""Owned TDX CDS recovery with SNP-backed custody; no shared host changes."""
import argparse
import base64
import datetime as dt
import json
import os
from pathlib import Path
import secrets
import signal
import sys
import tarfile
import time

from integrated import Integrated
from run import NS, VMI, LABEL, need, digest, image_inputs, resource_path, interrupt_run
from tdx_artifacts import image_inputs as tdx_inputs, check_fixture


class TDXIntegrated(Integrated):
    def is_tdx(self, vm):
        node = vm["spec"]["template"]["spec"]["nodeSelector"]["kubernetes.io/hostname"]
        return self.args.platforms[node] == "tdx"

    def verify_tdx(self, label, launch, custody=False):
        command = [self.args.probe, "-platform", "tdx", "-manifest", str(Path(self.args.tdx_image)/"manifest.json"),
            "-request", str(self.directory/(label+"-request.json")), "-launch", str(launch),
            "-receipt", str(self.directory/(label+"-receipt.json")), "-collateral", str(self.directory/(label+"-collateral.json"))]
        if custody: command.append("-custody-request")
        else: command.extend(["-reply", str(self.directory/(label+"-reply.json"))])
        self.command(label+"-verify", command, timeout=60)
        receipt = json.loads((self.directory/(label+"-receipt.json")).read_text())
        need(receipt.get("platform") == "tdx" and all(receipt.get(k) is True for k in (
            "attestation_chain_verified", "collateral_verified", "revocations_checked", "image_pins_verified", "launch_binding_verified")),
            "complete independently verified TDX evidence required")
        return receipt

    def phase_request(self, port, vm, phase, parameters, collateral):
        request = super().phase_request(port, vm, phase, parameters, collateral)
        if not self.is_tdx(vm): return request
        need(phase in ("seed", "recover"), "TDX can only receive CDS custody")
        label = phase+"-inspect"
        q = {"operation": "inspect", "nonce": base64.b64encode(secrets.token_bytes(32)).decode(),
             "measurement": self.state["tdx_pins"]["mrtd"], "parameters": {"guest_svn": 0, "tcb_version": 0}}
        self.atomic(self.directory/(label+"-request.json"), q)
        code, reply = self.http(port, "POST", "/v1/inspect", q)
        need(code == 200, "fresh TDX evidence unavailable before CDS phase")
        self.atomic(self.directory/(label+"-reply.json"), reply)
        self.verify_tdx(label, self.directory/"cds-launch.yaml")
        request["measurement"] = self.state["tdx_pins"]["mrtd"]
        request["intel_collateral"] = json.loads((self.directory/(label+"-collateral.json")).read_text())
        request.pop("collateral", None)
        return request

    def verify_phase(self, vm, phase, launch):
        if self.is_tdx(vm): return self.verify_tdx(phase, launch)
        return super().verify_phase(vm, phase, launch)

    def delegate(self, phase, request, parameters, collateral):
        need(request["path"] == "/pilot/"+self.state["prefix"]+"/custody", "custody scope mismatch")
        body = base64.b64decode(request["data"], validate=True)
        need(len(body) <= 128*1024, "custody request exceeds bound")
        recipient = json.loads(body)
        if recipient.get("family", "") == "":
            return super().delegate(phase, request, parameters, collateral)
        need(recipient.get("family") == "tdx" and phase in ("seed", "recover"), "unexpected custody family or phase")
        label, recipient_label = phase+"-custodian", phase+"-recipient"
        self.atomic(self.directory/(recipient_label+"-request.json"), recipient)
        self.verify_tdx(recipient_label, self.directory/"cds-launch.yaml", custody=True)
        q = {"operation": "delegate", "nonce": base64.b64encode(secrets.token_bytes(32)).decode(),
             "measurement": self.state["measurement"], "parameters": parameters, "collateral": collateral,
             "intel_collateral": json.loads((self.directory/(recipient_label+"-collateral.json")).read_text()), "custody": recipient}
        if self.custody_copy is not None: q["copy"] = self.custody_copy
        self.atomic(self.directory/(label+"-request.json"), q)
        code, _ = self.http(self.custodian_port, "POST", "/v1/start", q)
        need(code == 202, "SNP custody start refused or ambiguous")
        deadline = time.monotonic()+45
        while time.monotonic() < deadline:
            code, reply = self.http(self.custodian_port, "GET", "/v1/result")
            if code == 200: break
            need(code == 202, "SNP custody result unavailable")
            time.sleep(0.1)
        else: raise TimeoutError("SNP custody delegation deadline")
        self.atomic(self.directory/(label+"-reply.json"), reply)
        self.command(label+"-verify", [self.args.probe, "-request", str(self.directory/(label+"-request.json")),
            "-reply", str(self.directory/(label+"-reply.json")), "-launch", str(self.custodian_launch),
            "-receipt", str(self.directory/(label+"-receipt.json")), "-collateral", str(self.directory/(label+"-collateral.json"))], timeout=60)
        need(reply["result"]["derivation"] == self.custodian_identity, "SNP custody identity changed")
        return {"id": request["id"], "status": 200, "data": base64.b64encode(json.dumps(reply["result"]["custody"]).encode()).decode()}

    def render(self, run, node, uid, launch):
        if self.args.platforms[node] == "snp": return super().render(run, node, uid, launch)
        expiry = (dt.datetime.now(dt.timezone.utc)+dt.timedelta(minutes=45)).replace(microsecond=0).isoformat()
        items = json.loads(self.command(run+"-render", [self.args.renderer, "--platform", "tdx", "--run", run,
            "--node", node, "--node-uid", uid, "--launch-file", str(launch), "--expires", expiry,
            "--tools-image", self.args.tools_image]))["items"]
        check_fixture(items, run, node, uid)
        for item in items:
            path = resource_path(item)
            code, _ = self.kube.call("GET", path, expected=(200,404))
            need(code == 404, "new dedicated TDX resources required")
            self.kube.call("POST", path.rsplit("/",1)[0]+"?dryRun=All", item, expected=(201,))
        return items

    def populate(self, items, hashes, run):
        vm = next(i for i in items if i["kind"] == "VirtualMachine")
        if not self.is_tdx(vm): return super().populate(items, hashes, run)
        need(hashes == self.state["tdx_hashes"], "TDX population requires its own verified artifacts")
        for item in items:
            if item["kind"] != "VirtualMachine": self.create(item)
        pop = next(r for r in self.state["resources"] if r["item"]["metadata"]["name"] == run+"-populate")
        self.command(run+"-population-ready", self.kubectl("wait", "--for=condition=Ready", "pod/"+run+"-populate", "--timeout=180s"), timeout=190)
        for row in self.state["resources"]:
            if row["item"]["kind"] != "PersistentVolumeClaim": continue
            _, claim = self.kube.call("GET", row["path"])
            need(claim["metadata"]["uid"] == row["uid"], "owned claim replaced")
            _, pv = self.kube.call("GET", "/api/v1/persistentvolumes/"+claim["spec"]["volumeName"])
            need(pv["spec"]["claimRef"]["uid"] == row["uid"] and pv["spec"].get("persistentVolumeReclaimPolicy") == "Delete", "unexpected backing PV")
            row["pv"] = {"name": pv["metadata"]["name"], "uid": pv["metadata"]["uid"]}
            self.save()
        self.upload(run+"-populate", "tdx-root.tar.gz", "/rootdisk")
        actual = self.command(run+"-hashes", self.kubectl("exec", run+"-populate", "--", "sha256sum", "/rootdisk/disk.img")).decode().strip()
        need(actual == hashes["disk.raw"]+"  /rootdisk/disk.img", "uploaded TDX root mismatch")
        self.remove(pop)

    def exercise(self):
        import yaml
        cross_host = True
        need(len(self.args.nodes) == 4 and len(set(self.args.nodes)) == 4,
             "two independent SNP custody and two TDX CDS workers required")
        need(self.args.platforms == {n: "snp" if i < 2 else "tdx" for i,n in enumerate(self.args.nodes)},
             "explicit custody/receiver worker families required")
        direct_state = getattr(self.args, "direct_state", False)
        need(not direct_state or getattr(self.args, "metadata_relay", None), "direct state requires a frozen metadata relay")
        measurement, hashes = image_inputs(self.args.image)
        tdx_pins, tdx_hashes = tdx_inputs(self.args.tdx_image)
        self.state.update(tdx_pins=tdx_pins, tdx_hashes=tdx_hashes)
        need(not self.state["resources"], "new run directory required")
        self.state.update(artifact_hashes=hashes, measurement=measurement, prefix="integrated-" + secrets.token_hex(12), expected_product_line="Genoa")
        self.state["tool_hashes"] = {"verifier": digest(self.args.probe), "renderer": digest(self.args.renderer), "runner": digest(__file__)}
        self.state["direct_state"] = direct_state
        if direct_state:
            self.state["tool_hashes"]["metadata_relay"] = digest(self.args.metadata_relay)
            self.state["tool_hashes"]["metadata_process"] = digest(Path(__file__).with_name("metadata_process.py"))
        _, storage = self.kube.call("GET", "/apis/storage.k8s.io/v1/storageclasses/local-path")
        need(storage.get("reclaimPolicy") == "Delete" and storage.get("volumeBindingMode") == "WaitForFirstConsumer", "owned disk cleanup contract unavailable")
        baseline = self.health(capture=True)
        node = self.args.nodes[0]
        need(all(n in baseline for n in self.args.nodes), "approved custody or receiver worker missing")
        self.command("operator-key", ["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(self.directory / "operator.pem")])
        public = self.command("operator-public", ["openssl", "ec", "-in", str(self.directory / "operator.pem"), "-pubout"]).decode()
        config = {"schemaVersion": "c8s-cds/v1", "clusterID": "lane", "operatorPublicKeys": public,
                  "workloads": json.dumps({"schema": "c8s.allowlist/v1", "workloads": {"attestation-api": {"containers": [{"digest": "sha256:" + "11" * 32, "command": {"policy": "any"}, "args": {"policy": "any"}}]}}}),
                  "nodes": json.dumps({"schema_version": "1", "tee": "tdx", "measurements": [{"name": "node", "mrtd": tdx_pins["mrtd"], "rtmr": [None, tdx_pins["rtmr1"], tdx_pins["rtmr2"], None]}]}),
                  "nodeCIDRs": ["10.0.2.0/24"], "leafDNSNames": ["workload.lane.svc"],
                  "ha": {"replicas": ["127.0.77.1", "127.0.77.2", "127.0.77.3"], "voters": 3,
                         "objectWALPilot": {"bucket": "pilot", "region": "us-east-2", "prefix": self.state["prefix"], "endpoint": "https://127.0.0.1:9443", "pathStyle": True, "recoveryAuthority": base64.b64encode(bytes([1]) * 32).decode()}}}
        if direct_state:
            config["ha"]["objectWALPilot"].update(directState=True, atomicOperatorWrites=True, metadataEndpoint="https://127.0.0.1:9443")
        template = self.directory / "enrollment-launch.yaml"
        template.write_text(yaml.safe_dump(config, sort_keys=True))
        for archive, files in (("root.tar.gz", [("disk.raw", "disk.img")]), ("boot.tar.gz", [("guest-smp2.igvm", "guest-smp2.igvm"), ("manifest.json", "manifest.json")])):
            with tarfile.open(self.directory / archive, "w:gz", compresslevel=1) as tar:
                for src, dst in files: tar.add(Path(self.args.image) / src, arcname=dst, recursive=False)
        with tarfile.open(self.directory/"tdx-root.tar.gz", "w:gz", compresslevel=1) as tar:
            tar.add(Path(self.args.tdx_image)/"disk.raw", arcname="disk.img", recursive=False)
        custodian_run = "cds-snp-" + secrets.token_hex(6)
        custodian_items = self.render(custodian_run, node, baseline[node]["uid"], template)
        self.populate(custodian_items, hashes, custodian_run)
        custodian_vm = next(i for i in custodian_items if i["kind"] == "VirtualMachine")
        row, enrollment_vmi = self.boot(custodian_vm, "enroll")
        enrolled = self.phase(custodian_vm, "enroll", template, {"guest_svn": 0, "tcb_version": 0}, {})
        self.stop_forward(); self.remove(row); self.wait_absent(VMI + "/" + custodian_run)
        self.custodian_identity = enrolled["result"]["derivation"]
        self.custodian_launch = template
        self.custody_copy = None
        launch = self.directory / "cds-launch.yaml"
        launch.write_bytes(base64.b64decode(enrolled["result"]["launch"], validate=True))
        # Verify the attested enrollment changed exactly the authority public key.
        final = yaml.safe_load(launch.read_text())
        public_authority = final["ha"]["objectWALPilot"].pop("recoveryAuthority")
        original_authority = config["ha"]["objectWALPilot"].pop("recoveryAuthority")
        need(final == config and public_authority != original_authority, "enrollment changed unrelated launch settings")
        if "derivation" in enrolled["result"]:
            need(enrolled["result"]["derivation"]["authority_public"] == public_authority,
                 "two derivations in the enrollment guest produced different public authorities")
        # The custodian keeps its original HOST_DATA forever. Only the separate
        # CDS guest boots the completed public-authority configuration.
        run = "cds-tdx-" + secrets.token_hex(6)
        cds_source = self.args.nodes[2]
        items = self.render(run, cds_source, baseline[cds_source]["uid"], launch)
        self.populate(items, tdx_hashes, run)
        vm = next(i for i in items if i["kind"] == "VirtualMachine")
        parameters = enrolled["result"]["parameters"]
        collateral = json.loads((self.directory / "enroll-collateral.json").read_text())
        receipts, custody_receipts, vmis = [], [enrolled], [enrollment_vmi]
        destination_custodian_vm, destination_cds_vm, copied = None, None, None
        if cross_host:
            # Enroll the second chip while the original authority is available.
            # Populate every public disk before seed, so artifact upload cannot
            # consume the spent token's validity window during cold recovery.
            destination = self.args.nodes[1]
            destination_run = "cds-snp-" + secrets.token_hex(6)
            destination_items = self.render(destination_run, destination, baseline[destination]["uid"], launch)
            self.populate(destination_items, hashes, destination_run)
            destination_custodian_vm = next(i for i in destination_items if i["kind"] == "VirtualMachine")
            pair = self.boot_pair((("source", custodian_vm), ("destination", destination_custodian_vm)), "copy")
            self.custodian_port = self.tunnel(custodian_vm, "copy-source")
            copied = self.phase(destination_custodian_vm, "copy", launch, parameters, collateral)
            source_receipt = json.loads((self.directory / "copy-custodian-receipt.json").read_text())
            need(copied["chip_id_sha256"] != enrolled["chip_id_sha256"], "recovery copy must be on another physical chip")
            need(source_receipt["chip_id_sha256"] == enrolled["chip_id_sha256"], "unexpected source authority chip")
            need(copied["result"]["derivation"]["authority_public"] == public_authority,
                 "cross-host copy changed the recovery authority")
            self.atomic(self.directory / "custody-copy.json", copied["result"]["copy"])
            self.state["custody_copy_sha256"] = digest(self.directory / "custody-copy.json")
            self.event("cross-host-copy-persisted", source_node=node, destination_node=destination,
                       source_chip=enrolled["chip_id_sha256"], destination_chip=copied["chip_id_sha256"])
            self.stop_forward()
            for row, uid in pair.values():
                vmis.append(uid)
                self.remove(row)
                self.wait_absent(VMI + "/" + row["item"]["metadata"]["name"])
            custody_receipts.append(source_receipt)
            destination_run = "cds-tdx-" + secrets.token_hex(6)
            cds_destination = self.args.nodes[3]
            destination_items = self.render(destination_run, cds_destination, baseline[cds_destination]["uid"], launch)
            self.populate(destination_items, tdx_hashes, destination_run)
            destination_cds_vm = next(i for i in destination_items if i["kind"] == "VirtualMachine")
        for phase in ("seed", "recover"):
            self.health()
            if phase == "recover" and cross_host:
                self.custody_copy = json.loads((self.directory / "custody-copy.json").read_text())
                need(digest(self.directory / "custody-copy.json") == self.state["custody_copy_sha256"], "persisted copy changed")
                self.custodian_identity = copied["result"]["derivation"]
                self.custodian_launch = launch
                self.state["excluded_recovery_nodes"] = [node, cds_source]
                self.event("original-host-excluded-from-recovery", node=node)
                active_custodian, active_cds = destination_custodian_vm, destination_cds_vm
                collateral.update(json.loads((self.directory / "copy-collateral.json").read_text()))
            else:
                active_custodian, active_cds = custodian_vm, vm
            pair = self.boot_pair((("custodian", active_custodian), ("cds", active_cds)), phase)
            custody_row, custody_vmi = pair["custodian"]
            need(custody_vmi not in vmis, "new custodian VMI required")
            vmis.append(custody_vmi)
            self.custodian_port = self.tunnel(active_custodian, phase + "-custodian")
            row, vmi = pair["cds"]
            need(vmi not in vmis, "new VMI required")
            vmis.append(vmi)
            receipts.append(self.phase(active_cds, phase, launch, parameters, collateral))
            custody_receipts.append(json.loads((self.directory / (phase + "-custodian-receipt.json")).read_text()))
            self.stop_forward()
            self.remove(row)
            self.wait_absent(VMI + "/" + active_cds["metadata"]["name"])
            self.remove(custody_row)
            self.wait_absent(VMI + "/" + active_custodian["metadata"]["name"])
            self.event("all-cds-and-custodian-memory-destroyed", phase=phase, cds_vmi_uid=vmi, custodian_vmi_uid=custody_vmi)
        evidence = custody_receipts + [copied]
        need(len(set(vmis)) == 7, "seven distinct owned guest instances required")
        need(len({r["guest_report_id_sha256"] for r in evidence}) == 5, "five independent SNP custody guests required")
        need(len({r["chip_id_sha256"] for r in evidence}) == 2, "two independent SNP hardware roots required")
        need(custody_receipts[-1]["chip_id_sha256"] == copied["chip_id_sha256"], "recovery did not use surviving custody chip")
        need(all(r.get("platform") == "tdx" for r in receipts), "CDS phases must be independently verified native TDX")
        need(all(r["result"]["checks"].get("real_tdx_attestation") is True and
                 r["result"]["checks"].get("real_snp_attestation") is False for r in receipts), "wrong CDS hardware family")
        need(custody_receipts[-1]["launch_sha256"] == copied["launch_sha256"] == receipts[-1]["launch_sha256"], "mixed-platform launch binding changed")
        need(len({r["launch_sha256"] for r in custody_receipts[:-1]}) == 1, "original custody launch changed")
        self.state["cross_host_tdx_cds_recovery_passed"] = True
        need(len({r["launch_sha256"] for r in receipts}) == 1, "CDS launch changed")
        before, after = [r["result"]["checks"] for r in receipts]
        if direct_state:
            need(all(r["result"]["checks"].get("backend") == "transactional-current-state" and
                     r["result"]["checks"].get("authority_reads_current_records") is True for r in receipts),
                 "native receipt did not exercise current-state authority")
        need(before["ca_fingerprint"] == after["ca_fingerprint"], "independent CA receipts differ")
        need(all(after.get(k) is True for k in ("same_ca_all_replicas", "unexpired_replay_rejected_all_replicas", "revocation_preserved_all_replicas", "old_leaf_and_secret_positive_control", "attested_custodian_delegation")), "acceptance evidence incomplete")
        self.state["integrated_cds_recovery_passed"] = True
        self.state["full_acceptance_passed"] = False  # metadata HA, image retirement and custody membership remain separate
        self.event("integrated-cds-recovery-passed", ca_fingerprint=after["ca_fingerprint"], production_ready=False)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=["run", "cleanup"])
    for field in ("directory", "cloud-repo", "kubeconfig", "kubectl", "virtctl"):
        p.add_argument("--"+field, required=True)
    for field in ("image", "tdx-image", "renderer", "probe", "tools-image", "metadata-relay"):
        p.add_argument("--"+field)
    p.add_argument("--snp-nodes", nargs=2, default=[])
    p.add_argument("--tdx-nodes", nargs=2, default=[])
    args = p.parse_args()
    args.nodes = args.snp_nodes + args.tdx_nodes
    args.platforms = {**{n:"snp" for n in args.snp_nodes}, **{n:"tdx" for n in args.tdx_nodes}}
    args.direct_state = args.cross_host = True
    os.umask(0o077)
    Path(args.directory).mkdir(parents=True, exist_ok=True)
    sys.path.insert(0, str(Path(args.cloud_repo)/"integration/production"))
    from cds_ha_rehearsal import kube_client, atomic_json
    run = TDXIntegrated(args, kube_client(args.kubeconfig), atomic_json)
    if args.action == "cleanup":
        need(run.path.exists(), "cleanup requires the ownership journal")
        run.cleanup(); return
    need(all(getattr(args,f) for f in ("image", "tdx_image", "renderer", "probe", "tools_image", "metadata_relay")), "all independently built inputs required")
    for sig in (signal.SIGINT, signal.SIGTERM): signal.signal(sig, interrupt_run)
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError("45-minute mixed-platform deadline")))
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
