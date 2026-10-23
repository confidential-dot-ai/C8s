#!/usr/bin/env python3
"""Offline ownership and cleanup gates; these do not substitute for a TDX run."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "tdx-pod-diagnostic.py"
SPEC = importlib.util.spec_from_file_location("diagnostic", SCRIPT)
diagnostic = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(diagnostic)


class OwnershipTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.task = diagnostic.Diagnostic(Path(self.temp.name), "123", "2", "confidential-dot-ai/C8s")

    def object(self, suffix=""):
        meta = self.task.metadata(suffix)
        meta.update(uid="owned-uid", resourceVersion="17")
        return {"metadata": meta}

    def ledger(self, kind="vm", suffix=""):
        self.task.metadata(suffix)
        diagnostic.write(self.task.ledger, [{"kind": kind, "suffix": suffix, "uid": "owned-uid"}])

    def test_scope_and_attempt_are_required(self):
        for run, attempt, repo in [("../123", "2", "confidential-dot-ai/C8s"),
                                   ("123", "", "confidential-dot-ai/C8s"), ("123", "2", "foreign/C8s")]:
            with self.assertRaises(RuntimeError):
                diagnostic.Diagnostic(Path(self.temp.name), run, attempt, repo)
        for field, key, value in [("metadata", "namespace", "default"),
                                  ("labels", "ci.confidential.ai/run-attempt", "1"),
                                  ("labels", "ci.confidential.ai/run-id", "456"),
                                  ("annotations", "ci.confidential.ai/repo", "foreign/C8s")]:
            obj = self.object()
            target = obj["metadata"] if field == "metadata" else obj["metadata"][field]
            target[key] = value
            with self.assertRaises(RuntimeError):
                self.task.owned(obj, "", "owned-uid")

    def test_create_refuses_existing_even_with_matching_labels(self):
        with patch.object(diagnostic, "kube", return_value=self.object()) as kube:
            with self.assertRaises(RuntimeError):
                self.task.create("vm", "", self.task.vm())
        self.assertEqual(kube.call_count, 1)
        self.assertFalse(self.task.ledger.exists())

    def test_create_records_unknown_outcome_for_cleanup(self):
        with patch.object(diagnostic, "kube", side_effect=[None, TimeoutError("lost response")]):
            with self.assertRaises(TimeoutError):
                self.task.create("vm", "", self.task.vm())
        self.assertEqual(self.task.resources(), [{"kind": "vm", "suffix": "", "uid": None}])

    def test_unknown_create_outcome_does_not_adopt_another_request(self):
        spec = self.task.vm()
        with patch.object(diagnostic, "kube", side_effect=[None, RuntimeError("AlreadyExists")]):
            with self.assertRaises(RuntimeError):
                self.task.create("vm", "", spec)
        replacement = self.object()
        replacement["metadata"]["annotations"]["ci.confidential.ai/creation-nonce"] = "foreign-request"
        with patch.object(diagnostic, "kube", return_value=replacement) as kube:
            with self.assertRaisesRegex(RuntimeError, "ownership differs"):
                self.task.remove("vm", "")
        self.assertEqual(kube.call_count, 1)

    def test_creation_nonce_is_per_resource_and_survives_cleanup_process(self):
        first = self.task.metadata("")["annotations"]["ci.confidential.ai/creation-nonce"]
        second = self.task.metadata("-root")["annotations"]["ci.confidential.ai/creation-nonce"]
        self.assertNotEqual(first, second)
        resumed = diagnostic.Diagnostic(self.task.root, "123", "2", "confidential-dot-ai/C8s")
        self.assertEqual(resumed.metadata("")["annotations"]["ci.confidential.ai/creation-nonce"], first)

    def test_failed_atomic_write_preserves_the_existing_ledger(self):
        self.ledger()
        before = self.task.ledger.read_bytes()
        with patch.object(Path, "replace", side_effect=OSError("interrupted publication")):
            with self.assertRaises(OSError):
                diagnostic.write(self.task.ledger, [])
        self.assertEqual(self.task.ledger.read_bytes(), before)
        self.assertEqual(list(self.task.private.glob("*.tmp")), [])

    def test_request_budget_does_not_outlive_the_phase(self):
        with patch.object(diagnostic.time, "monotonic", return_value=100):
            self.assertEqual(diagnostic.budget(107), 7)
            self.assertEqual(diagnostic.budget(200), 30)
            with self.assertRaises(RuntimeError):
                diagnostic.budget(100)

    def test_cleanup_rejects_replaced_resource_before_delete(self):
        self.ledger()
        replaced = self.object()
        replaced["metadata"]["uid"] = "replacement"
        with patch.object(diagnostic, "kube", return_value=replaced) as kube:
            with self.assertRaises(RuntimeError):
                self.task.remove("vm", "")
        self.assertEqual(kube.call_count, 1)

    def test_delete_is_uid_preconditioned(self):
        self.ledger()
        with patch.object(diagnostic, "kube", side_effect=[self.object(), b"{}", None]) as kube:
            self.task.remove("vm", "")
        args, kwargs = kube.call_args_list[1]
        self.assertEqual(args[:2], ("delete", "--raw"))
        self.assertIn("/namespaces/confai-images/virtualmachines/c8s-poddiag-123-2", args[2])
        self.assertEqual(json.loads(kwargs["data"])["preconditions"], {"uid": "owned-uid"})

    def test_failed_vm_cleanup_retains_dependencies(self):
        diagnostic.write(self.task.ledger, [{"kind": "pvc", "suffix": "-root", "uid": "root"},
                                            {"kind": "vm", "suffix": "", "uid": "owned-uid"}])
        with patch.object(self.task, "remove", side_effect=RuntimeError("VM still present")) as remove:
            with self.assertRaises(RuntimeError):
                self.task.cleanup()
        remove.assert_called_once_with("vm", "")
        self.assertFalse(json.loads((self.task.evidence/"cleanup.json").read_text())["complete"])

    def test_foreign_launcher_is_not_read(self):
        vm = self.object()
        vmi = {"metadata": {"uid": "vmi-owned", "ownerReferences": [
            {"controller": True, "kind": "VirtualMachine", "uid": "owned-uid"}]}}
        pod = {"metadata": {"name": "foreign", "ownerReferences": [
            {"controller": True, "kind": "VirtualMachineInstance", "uid": "vmi-foreign"}]}}
        with patch.object(self.task, "get", return_value=vm), patch.object(diagnostic, "kube", side_effect=[vmi, {"items": [pod]}]) as kube:
            with self.assertRaises(RuntimeError):
                self.task.capture(0)
        self.assertEqual(kube.call_count, 2)

    def test_vm_has_private_readonly_root_and_no_extra_host_inputs(self):
        vm = self.task.vm()
        spec = vm["spec"]["template"]["spec"]
        self.assertEqual(vm["spec"]["runStrategy"], "Once")
        self.assertEqual(spec["domain"]["launchSecurity"], {"tdx": {}})
        self.assertEqual(spec["domain"]["cpu"]["model"], "host-passthrough")
        self.assertTrue(spec["domain"]["devices"]["logSerialConsole"])
        self.assertTrue(spec["domain"]["devices"]["disks"][0]["disk"]["readonly"])
        self.assertEqual(spec["volumes"], [
            {"name": "rootdisk", "persistentVolumeClaim": {"claimName": self.task.name + "-root"}},
            {"name": "opkey", "secret": {"secretName": self.task.name + "-opkey", "volumeLabel": "opkeydata"}}])

    def test_manifest_rejects_changed_bytes_before_parsing(self):
        for data in (b"{}", b"x" * 65537, b'{"tdx":{"mrtd":"forged"}}'):
            with self.assertRaisesRegex(RuntimeError, "manifest digest differs"):
                diagnostic.validate_manifest(data)

    def test_manifest_requires_paired_disk_and_all_tdx_registers(self):
        manifest = {"inputs": {"base_image": {"sha256": diagnostic.DISK}},
                    "tdx": {"mrtd": "a" * 96, "rtmr1": "b" * 96, "rtmr2": "c" * 96}}
        data = json.dumps(manifest).encode()
        with patch.object(diagnostic, "MANIFEST", hashlib.sha256(data).hexdigest()):
            self.assertEqual(diagnostic.validate_manifest(data), manifest)
        bad_disk = copy.deepcopy(manifest)
        bad_disk["inputs"]["base_image"]["sha256"] = "0" * 64
        missing_register = copy.deepcopy(manifest)
        missing_register["tdx"]["rtmr2"] = ""
        for bad in (bad_disk, missing_register):
            data = json.dumps(bad).encode()
            with patch.object(diagnostic, "MANIFEST", hashlib.sha256(data).hexdigest()), self.assertRaises(RuntimeError):
                diagnostic.validate_manifest(data)


if __name__ == "__main__":
    unittest.main()
