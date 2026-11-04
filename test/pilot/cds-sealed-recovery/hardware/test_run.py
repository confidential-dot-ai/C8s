import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import subprocess
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

    def test_archive_finishes_while_transport_stdin_stays_open(self):
        archive = io.BytesIO()
        payload = b"bounded disposable artifact" * 20
        with tarfile.open(fileobj=archive, mode="w:gz") as tar:
            info = tarfile.TarInfo("disk.img")
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))
        body = archive.getvalue()
        process = subprocess.Popen(module.archive_receiver(len(body), self.tmp.name), stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            process.stdin.write(body)
            process.stdin.flush()
            self.assertEqual(0, process.wait(timeout=5))  # deliberately keep stdin open
            self.assertEqual(payload, (Path(self.tmp.name) / "disk.img").read_bytes())
        finally:
            process.stdin.close()
            if process.poll() is None:
                process.kill()
            process.wait()
            process.stdout.close()
            process.stderr.close()

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
