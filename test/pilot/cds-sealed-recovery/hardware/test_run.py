import copy
import hashlib
import importlib.util
import io
import json
import signal
from pathlib import Path
import tempfile
import subprocess
import sys
import tarfile
import types
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("snp_run", Path(__file__).with_name("run.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class FakeKube:
    def __init__(self, obj=None):
        self.obj, self.calls = obj, []
        self.lose_post_response = False

    def call(self, method, path, body=None, **kwargs):
        self.calls.append((method, path, body))
        if method == "GET":
            return (200, copy.deepcopy(self.obj)) if self.obj else (404, None)
        if method == "POST":
            self.obj = copy.deepcopy(body)
            self.obj["metadata"]["uid"] = "created-uid"
            if self.lose_post_response:
                raise TimeoutError("POST response lost")
            return 201, copy.deepcopy(self.obj)
        if method == "DELETE":
            assert body["preconditions"]["uid"] == self.obj["metadata"]["uid"]
            self.obj = None
            return 200, None
        raise AssertionError(method)


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.item = {"apiVersion": "v1", "kind": "Pod", "metadata": {
            "namespace": "p-internal", "name": "cds-snp-0123456789ab-populate",
            "labels": {module.LABEL: "cds-snp-0123456789ab"}}}

    def runner(self, kube):
        args = types.SimpleNamespace(directory=self.tmp.name)
        return module.Run(args, kube, lambda p, v: Path(p).write_text(json.dumps(v)))

    def test_interrupt_escapes_child_wait_to_reach_cleanup(self):
        previous = signal.signal(signal.SIGINT, module.interrupt_run)
        self.addCleanup(signal.signal, signal.SIGINT, previous)
        cleaned = False
        with self.assertRaisesRegex(SystemExit, "test interrupted"):
            try:
                subprocess.run([sys.executable, "-c",
                    "import os,signal,sys,time; sys.stdin.buffer.read(1); "
                    "os.kill(os.getppid(),signal.SIGINT); time.sleep(30)"],
                    input=b"ready", check=True, timeout=5)
            finally:
                cleaned = True
        self.assertTrue(cleaned)

    def health_runner(self):
        owner_path = "/apis/kubevirt.io/v1/namespaces/customer/virtualmachines/existing"
        vmi = {"metadata": {"namespace": "customer", "name": "existing", "uid": "vmi-uid",
                "ownerReferences": [{"apiVersion": "kubevirt.io/v1", "kind": "VirtualMachine",
                                     "name": "existing", "uid": "vm-uid", "controller": True}]},
               "status": {"phase": "Running", "conditions": [{"type": "Ready", "status": "True"}]}}

        class HealthKube:
            def __init__(self):
                self.calls = []
                self.objects = {"/api/v1/nodes": {"items": []},
                    "/apis/kubevirt.io/v1/virtualmachineinstances": {"items": [vmi]},
                    owner_path: {"metadata": {"uid": "vm-uid"}}}

            def call(self, method, path, *args, **kwargs):
                self.calls.append((method, path))
                assert method == "GET", "health observation must never mutate resources"
                return (200, copy.deepcopy(self.objects[path])) if path in self.objects else (404, None)

        kube = HealthKube()
        run = self.runner(kube)
        run.args.nodes = []
        run.health(capture=True)
        return run, kube, owner_path, vmi

    def test_declared_vm_deletion_is_recorded_as_changed_fleet(self):
        run, kube, owner_path, vmi = self.health_runner()
        vmi["status"]["conditions"][0]["status"] = "False"
        kube.objects[owner_path]["metadata"]["deletionTimestamp"] = "2026-11-04T01:00:00Z"
        run.health()
        self.assertIn("vmi-uid", run.state["external_vm_deletions"])
        self.assertEqual(200, run.state["external_vm_deletions"]["vmi-uid"]["owner_http_status"])
        self.assertEqual("external-vm-deletion-observed", run.state["events"][-1]["event"])

    def test_missing_vm_owner_is_recorded_without_ignoring_unknown_vmi_loss(self):
        run, kube, owner_path, vmi = self.health_runner()
        kube.objects["/apis/kubevirt.io/v1/virtualmachineinstances"]["items"] = []
        del kube.objects[owner_path]
        run.health()
        self.assertEqual(404, run.state["external_vm_deletions"]["vmi-uid"]["owner_http_status"])
        run.state["vmis_before"]["vmi-uid"]["vm_owner"] = None
        with self.assertRaisesRegex(RuntimeError, "owner unknown"):
            run.health()

    def test_unexpected_vmi_loss_or_readiness_regression_still_stops(self):
        for missing, replaced_owner in ((False, False), (True, False), (True, True)):
            with self.subTest(missing=missing, replaced_owner=replaced_owner):
                run, kube, owner_path, vmi = self.health_runner()
                if missing:
                    kube.objects["/apis/kubevirt.io/v1/virtualmachineinstances"]["items"] = []
                else:
                    vmi["status"]["conditions"][0]["status"] = "False"
                if replaced_owner:
                    kube.objects[owner_path]["metadata"].update(uid="replacement", deletionTimestamp="2026-11-04T01:00:00Z")
                with self.assertRaisesRegex(RuntimeError, "without explicit owning VM stop/deletion"):
                    run.health()

    def test_explicit_vm_halt_is_recorded_as_external_change(self):
        for missing in (False, True):
            with self.subTest(missing=missing):
                run, kube, owner_path, vmi = self.health_runner()
                kube.objects[owner_path]["spec"] = {"runStrategy": "Halted"}
                if missing:
                    kube.objects["/apis/kubevirt.io/v1/virtualmachineinstances"]["items"] = []
                else:
                    vmi["status"]["conditions"][0]["status"] = "False"
                run.health()
                self.assertEqual("Halted", run.state["external_vm_stops"]["vmi-uid"]["run_strategy"])
                self.assertEqual("external-vm-stop-observed", run.state["events"][-1]["event"])
                self.assertNotIn("external_vm_deletions", run.state)

    def test_stopped_status_or_replaced_halted_owner_is_not_stop_authority(self):
        for replaced in (False, True):
            with self.subTest(replaced=replaced):
                run, kube, owner_path, vmi = self.health_runner()
                kube.objects["/apis/kubevirt.io/v1/virtualmachineinstances"]["items"] = []
                vm = kube.objects[owner_path]
                vm["status"] = {"printableStatus": "Stopped"}
                vm["spec"] = {"runStrategy": "Halted" if replaced else "Always"}
                if replaced:
                    vm["metadata"]["uid"] = "replacement"
                with self.assertRaisesRegex(RuntimeError, "without explicit owning VM stop/deletion"):
                    run.health()
                self.assertNotIn("external_vm_stops", run.state)

    def test_live_process_with_dead_tunnel_is_replaced_before_retry(self):
        run = self.runner(FakeKube())
        run.args.virtctl, run.args.kubeconfig, run.args.probe = "virtctl", "test-config", "probe"
        run.args.product_line = "Genoa"
        processes = []

        class Forwarder:
            stopped = False

            def poll(self):
                return 0 if self.stopped else None

            def terminate(self):
                self.stopped = True

            def wait(self, **kwargs):
                return 0

        def spawn(*args, **kwargs):
            process = Forwarder()
            processes.append(process)
            return process

        def request(*args, **kwargs):
            command = args[1]
            self.assertEqual("Genoa", command[command.index("-product-line") + 1])
            if len(processes) == 1:
                # The process remains alive even though it accepts no more
                # connections after the initial guest-dial failure.
                self.assertIsNone(processes[0].poll())
                raise RuntimeError("guest was not ready")
            self.assertTrue(processes[0].stopped)
            return b'{"verified_receipt":true}'

        run.command = request
        try:
            with patch.object(module.subprocess, "Popen", side_effect=spawn), \
                 patch.object(module.time, "sleep"), patch.object(module.socket, "socket") as local_socket:
                local_socket.return_value.__enter__.return_value.getsockname.return_value = ("127.0.0.1", 24445)
                result = run.probe({"metadata": {"name": "owned-vm"}}, "seal", "seal", "sealed", "measured-image")
            self.assertEqual({"verified_receipt": True}, result)
            self.assertEqual(2, len(processes))
            self.assertEqual("vm-tunnel-restarted", run.state["events"][-1]["event"])
        finally:
            run.stop_forward()
        self.assertTrue(all(p.stopped for p in processes))

    def test_archive_finishes_while_transport_stdin_stays_open(self):
        archive = io.BytesIO()
        payload = b"bounded disposable artifact" * 20
        with tarfile.open(fileobj=archive, mode="w:gz") as tar:
            info = tarfile.TarInfo("disk.img")
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))
        body = archive.getvalue()
        token = "ab" * 16
        process = subprocess.Popen(module.archive_receiver(len(body), self.tmp.name, token), stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            process.stdin.write(body)
            process.stdin.flush()
            self.assertEqual(0, process.wait(timeout=5))  # deliberately keep stdin open
            self.assertEqual(payload, (Path(self.tmp.name) / "disk.img").read_bytes())
            self.assertEqual(token, (Path(self.tmp.name) / ".cds-upload-complete").read_text())
        finally:
            process.stdin.close()
            if process.poll() is None:
                process.kill()
            process.wait()
            process.stdout.close()
            process.stderr.close()

    def test_probe_network_rule_refuses_broader_targets_peers_or_ports(self):
        name = "cds-snp-0123456789ab"
        policy = {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": name, "namespace": "p-internal", "labels": {module.LABEL: name}},
            "spec": {"podSelector": {"matchLabels": {module.LABEL: name, "kubevirt.io/domain": name}},
                "policyTypes": ["Ingress"], "ingress": [{"ports": [{"protocol": "TCP", "port": 6443}],
                "from": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kubevirt"}},
                          "podSelector": {"matchLabels": {"kubevirt.io": "virt-api"}}}]}]}}
        module.check_probe_network_policy(policy, name)
        for mutation in (lambda p: p["spec"].update(podSelector={}),
                         lambda p: p["spec"]["ingress"][0]["from"][0].update(namespaceSelector={}),
                         lambda p: p["spec"]["ingress"][0]["ports"][0].update(port=443),
                         lambda p: p["spec"].update(egress=[{}])):
            changed = copy.deepcopy(policy)
            mutation(changed)
            with self.assertRaises(RuntimeError):
                module.check_probe_network_policy(changed, name)

    def test_compressed_expansion_emits_progress_and_preserves_bytes(self):
        payload = b"\0" * (21 * 1024**2)
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w:gz") as tar:
            info = tarfile.TarInfo("disk.img")
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))
        body = archive.getvalue()
        result = subprocess.run(module.archive_receiver(len(body), self.tmp.name), input=body,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        self.assertEqual(0, result.returncode)
        self.assertGreaterEqual(len(result.stderr.splitlines()), 2)
        self.assertEqual(hashlib.sha256(payload).hexdigest(), module.digest(Path(self.tmp.name) / "disk.img"))

    def test_invalid_archive_never_marks_completion(self):
        result = subprocess.run(module.archive_receiver(7, self.tmp.name, "ab" * 16), input=b"invalid",
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        self.assertNotEqual(0, result.returncode)
        self.assertFalse((Path(self.tmp.name) / ".cds-upload-complete").exists())

    def test_upload_finishes_when_stream_client_never_reports_exit(self):
        root = Path(self.tmp.name)
        destination = root / "destination"
        destination.mkdir()
        payload = b"complete public artifact"
        with tarfile.open(root / "root.tar.gz", "w:gz") as tar:
            info = tarfile.TarInfo("disk.img")
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))
        run = self.runner(FakeKube())

        def local_exec(*args):
            command = list(args[args.index("--") + 1:])
            if "-i" in args:
                # The remote command finishes; its client waits indefinitely.
                return [sys.executable, "-c", "import subprocess,signal,sys; "
                        "subprocess.run(sys.argv[1:],check=True); signal.pause()", *command]
            return command

        run.kubectl = local_exec
        run.upload("owned-populate", "root.tar.gz", str(destination))
        self.assertEqual(payload, (destination / "disk.img").read_bytes())
        self.assertEqual("upload-receiver-completed", run.state["events"][-1]["event"])
        self.assertTrue(run.state["events"][-1]["client_exit_pending"])

    def test_receiver_can_complete_after_client_connection_fails(self):
        root = Path(self.tmp.name)
        destination = root / "destination"
        destination.mkdir()
        payload = b"already delivered public artifact"
        with tarfile.open(root / "root.tar.gz", "w:gz") as tar:
            info = tarfile.TarInfo("disk.img")
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))
        run = self.runner(FakeKube())
        receivers = []

        def local_exec(*args):
            command = list(args[args.index("--") + 1:])
            if "-i" in args:
                # Independently model a receiver finishing buffered input after
                # the client loses its connection. The failed client itself
                # supplies neither a completion receipt nor a success status.
                with (root / "root.tar.gz").open("rb") as data:
                    receivers.append(subprocess.Popen([sys.executable, "-c",
                        "import subprocess,sys,time; time.sleep(1); "
                        "subprocess.run(sys.argv[1:],check=True)", *command], stdin=data,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
                return [sys.executable, "-c", "raise SystemExit(1)"]
            return command

        run.kubectl = local_exec
        try:
            run.upload("owned-populate", "root.tar.gz", str(destination))
            self.assertEqual(payload, (destination / "disk.img").read_bytes())
            self.assertEqual(1, run.state["events"][-1]["client_returncode"])
        finally:
            for process in receivers:
                if process.poll() is None:
                    process.terminate()
                process.wait(timeout=5)

    def test_lost_completion_read_does_not_abort_or_establish_upload(self):
        root = Path(self.tmp.name)
        destination = root / "destination"
        destination.mkdir()
        payload = b"receiver must finish before a later authenticated read succeeds"
        with tarfile.open(root / "root.tar.gz", "w:gz") as tar:
            info = tarfile.TarInfo("disk.img")
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))
        run = self.runner(FakeKube())
        reads = 0

        def local_exec(*args):
            nonlocal reads
            command = list(args[args.index("--") + 1:])
            if "-i" in args:
                return [sys.executable, "-c", "import subprocess,signal,sys,time; "
                        "time.sleep(1); subprocess.run(sys.argv[1:],check=True); signal.pause()", *command]
            reads += 1
            if reads == 1:
                return [sys.executable, "-c", "raise SystemExit(1)"]
            return command

        run.kubectl = local_exec
        run.upload("owned-populate", "root.tar.gz", str(destination))
        self.assertEqual(payload, (destination / "disk.img").read_bytes())
        self.assertGreaterEqual(reads, 2)
        self.assertEqual(["upload-completion-unavailable", "upload-receiver-completed"],
                         [e["event"] for e in run.state["events"]])

    def test_cleanup_refuses_changed_owner_uid_or_journal_path(self):
        for change in ("uid", "owner", "path"):
            with self.subTest(change=change):
                obj = copy.deepcopy(self.item)
                obj["metadata"]["uid"] = "ours"
                row = {"item": self.item, "path": module.resource_path(self.item), "uid": "ours"}
                if change == "uid":
                    obj["metadata"]["uid"] = "replacement"
                elif change == "owner":
                    obj["metadata"]["labels"][module.LABEL] = "someone-else"
                else:
                    row["path"] = "/api/v1/namespaces/production/pods/customer"
                kube = FakeKube(obj)
                with self.assertRaises(RuntimeError):
                    self.runner(kube).remove(row)
                self.assertFalse(any(method == "DELETE" for method, _, _ in kube.calls))

    def test_lost_create_response_recovered_from_durable_intent(self):
        kube = FakeKube()
        kube.lose_post_response = True
        run = self.runner(kube)
        with self.assertRaises(TimeoutError):
            run.create(self.item)
        restarted = self.runner(kube)
        self.assertIsNone(restarted.state["resources"][0]["uid"])
        restarted.remove(restarted.state["resources"][0])
        self.assertIsNone(kube.obj)
        self.assertEqual("created-uid", restarted.state["resources"][0]["uid"])

    def test_transient_create_reconciles_before_retry_and_stays_bounded(self):
        for outcome in ("absent", "already-created", "persistent-failure"):
            with self.subTest(outcome=outcome):
                class TransientKube(FakeKube):
                    posts = 0

                    def call(self, method, path, body=None, **kwargs):
                        if method == "POST":
                            self.posts += 1
                            if outcome == "already-created":
                                super().call(method, path, body, **kwargs)
                                return 500, None
                            if outcome == "persistent-failure" or self.posts == 1:
                                self.calls.append((method, path, body))
                                return 503, None
                        return super().call(method, path, body, **kwargs)

                kube = TransientKube()
                run = self.runner(kube)
                run.state["resources"] = []
                with patch.object(module.time, "sleep"):
                    if outcome == "persistent-failure":
                        with self.assertRaisesRegex(RuntimeError, "three transient API"):
                            run.create(self.item)
                        self.assertEqual(3, kube.posts)
                    else:
                        row = run.create(self.item)
                        self.assertEqual("created-uid", row["uid"])
                        self.assertEqual(1 if outcome == "already-created" else 2, kube.posts)
                self.assertEqual(1, len(run.state["resources"]))
                for index, (method, _, _) in enumerate(kube.calls):
                    if method == "POST" and index:
                        self.assertEqual("GET", kube.calls[index - 1][0])

    def test_failed_create_never_adopts_another_owner(self):
        class CollisionKube(FakeKube):
            def call(self, method, path, body=None, **kwargs):
                result = super().call(method, path, body, **kwargs)
                if method == "POST":
                    self.obj["metadata"]["labels"][module.LABEL] = "someone-else"
                    return 500, None
                return result

        kube = CollisionKube()
        with self.assertRaisesRegex(RuntimeError, "owner mismatch"):
            self.runner(kube).create(self.item)
        self.assertEqual(1, sum(method == "POST" for method, _, _ in kube.calls))

    def test_existing_resource_is_never_adopted(self):
        kube = FakeKube(self.item)
        run = self.runner(kube)
        with self.assertRaises(RuntimeError):
            run.create(self.item)
        self.assertEqual([], run.state["resources"])
        self.assertFalse(any(method == "POST" for method, _, _ in kube.calls))

    def test_cleanup_waits_for_volume_after_claim_delete_response_is_lost(self):
        item = copy.deepcopy(self.item)
        item["kind"] = "PersistentVolumeClaim"
        item["metadata"]["name"] = "cds-snp-0123456789ab-root"
        row = {"item": item, "path": module.resource_path(item), "uid": "claim-uid",
               "pv": {"name": "owned-pv", "uid": "volume-uid"}}

        class ReclaimingKube(FakeKube):
            volume_reads = 0

            def call(self, method, path, body=None, **kwargs):
                if path == "/api/v1/persistentvolumes/owned-pv":
                    self.volume_reads += 1
                    return (200, {}) if self.volume_reads == 1 else (404, None)
                return super().call(method, path, body, **kwargs)

        kube = ReclaimingKube()
        run = self.runner(kube)
        with patch.object(module.time, "sleep"):
            run.remove(row)
        self.assertEqual(2, kube.volume_reads)
        self.assertTrue(row["deleted"])
        self.assertFalse(any(method == "DELETE" for method, _, _ in kube.calls))

    def test_cleanup_discovers_volume_after_population_failure(self):
        item = copy.deepcopy(self.item)
        item["kind"] = "PersistentVolumeClaim"
        item["metadata"]["name"] = "cds-snp-0123456789ab-root"
        current = copy.deepcopy(item)
        current["metadata"]["uid"] = "claim-uid"
        current["spec"] = {"volumeName": "owned-pv"}

        class BoundKube(FakeKube):
            def call(self, method, path, body=None, **kwargs):
                if method == "GET" and path == "/api/v1/persistentvolumes/owned-pv":
                    return (200, {"metadata": {"uid": "volume-uid"}, "spec": {
                        "claimRef": {"uid": "claim-uid"}, "persistentVolumeReclaimPolicy": "Delete"}}) if self.obj else (404, None)
                return super().call(method, path, body, **kwargs)

        kube = BoundKube(current)
        run = self.runner(kube)
        row = {"item": item, "path": module.resource_path(item), "uid": "claim-uid"}
        run.state["resources"].append(row)
        run.remove(row)
        self.assertEqual({"name": "owned-pv", "uid": "volume-uid"}, row["pv"])
        self.assertTrue(row["deleted"])
        self.assertEqual([row["path"]], [path for method, path, _ in kube.calls if method == "DELETE"])

    def test_artifact_substitution_refused_before_cluster_access(self):
        root = Path(self.tmp.name)
        entries = {}
        for name in ("disk.raw", "guest-smp2.igvm", "uki.efi", "OVMF.fd"):
            content = ("fixture:" + name).encode()
            (root / name).write_bytes(content)
            entries[name] = {"path": name, "sha256": hashlib.sha256(content).hexdigest()}
        manifest = {"version":3, "build":{"memory":"4G"},
            "outputs":{"disk_image":entries["disk.raw"],"uki":entries["uki.efi"]},
            "inputs":{"firmware":entries["OVMF.fd"]},
            "snp_variants":[{"smp":2,"igvm":entries["guest-smp2.igvm"],"measurement":{"snp_launch_digest":"ab"*48}}]}
        (root / "manifest.json").write_text(json.dumps(manifest))
        self.assertEqual("ab"*48, module.image_inputs(root)[0])
        (root / "disk.raw").write_bytes(b"changed")
        with self.assertRaisesRegex(RuntimeError, "hash mismatch"):
            module.image_inputs(root)
        manifest["outputs"]["disk_image"]["path"] = "../disk.raw"
        (root / "manifest.json").write_text(json.dumps(manifest))
        with self.assertRaisesRegex(RuntimeError, "unexpected artifact path"):
            module.image_inputs(root)


if __name__ == "__main__":
    unittest.main()
