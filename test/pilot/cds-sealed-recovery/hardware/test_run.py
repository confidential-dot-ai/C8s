import copy
import hashlib
import importlib.util
import io
import json
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
                with self.assertRaisesRegex(RuntimeError, "without owning VM deletion"):
                    run.health()

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
