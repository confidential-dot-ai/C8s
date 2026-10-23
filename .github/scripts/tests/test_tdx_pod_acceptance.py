#!/usr/bin/env python3
"""Offline gates for the native hardware harness, not hardware substitutes."""
import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
import tdx_pod_resources as resources
spec = importlib.util.spec_from_file_location("acceptance", SCRIPTS / "tdx-pod-acceptance.py")
acceptance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acceptance)


class HarnessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.task = resources.OwnedResources(Path(self.temp.name), "123", "2", "confidential-dot-ai/C8s")

    def object(self, suffix="-a", uid="owned", kind="vm"):
        meta = self.task.metadata(kind, suffix)
        meta.update(uid=uid, resourceVersion="9")
        return {"metadata": meta}

    def intent(self, kind="vm", suffix="-a", uid="owned"):
        self.task.metadata(kind, suffix)
        resources.write(self.task.ledger, [{"kind": kind, "suffix": suffix, "uid": uid}])

    def test_no_existing_resource_is_adopted(self):
        with patch.object(resources, "kube", return_value=self.object()) as kube:
            with self.assertRaises(RuntimeError):
                self.task.create("vm", "-a", {})
        self.assertEqual(kube.call_count, 1)
        self.assertFalse(self.task.ledger.exists())

    def test_unknown_create_outcome_requires_the_exact_creation_nonce(self):
        with patch.object(resources, "kube", side_effect=[None, TimeoutError("unknown outcome")]):
            with self.assertRaises(TimeoutError):
                self.task.create("vm", "-a", {})
        self.assertIsNone(self.task.resources()[0]["uid"])
        other = self.object(uid="replacement")
        other["metadata"]["annotations"]["ci.confidential.ai/creation-nonce"] = "different-request"
        with patch.object(resources, "kube", return_value=other) as kube:
            with self.assertRaises(RuntimeError):
                self.task.remove("vm", "-a")
        self.assertEqual(kube.call_count, 1)

    def test_cross_kind_creation_intents_never_share_a_nonce(self):
        service = self.task.metadata("service", "-a")
        vm = self.task.metadata("vm", "-a")
        self.assertNotEqual(service["annotations"]["ci.confidential.ai/creation-nonce"], vm["annotations"]["ci.confidential.ai/creation-nonce"])
        self.intent(uid=None)
        copied = self.object()
        copied["metadata"]["annotations"]["ci.confidential.ai/creation-nonce"] = service["annotations"]["ci.confidential.ai/creation-nonce"]
        with patch.object(resources, "kube", return_value=copied) as kube:
            with self.assertRaises(RuntimeError): self.task.remove("vm", "-a")
        self.assertEqual(kube.call_count, 1)

    def test_scope_or_uid_mismatch_never_deletes(self):
        self.intent()
        for field, key, value in [("metadata", "uid", "other"), ("metadata", "namespace", "default"),
                                  ("labels", "ci.confidential.ai/run-attempt", "3"), ("annotations", "ci.confidential.ai/repo", "foreign/C8s")]:
            obj = self.object()
            target = obj["metadata"] if field == "metadata" else obj["metadata"][field]
            target[key] = value
            with patch.object(resources, "kube", return_value=obj) as kube:
                with self.assertRaises(RuntimeError):
                    self.task.remove("vm", "-a")
            self.assertEqual(kube.call_count, 1)

    def test_services_delete_with_uid_precondition(self):
        self.intent("service")
        with patch.object(resources, "kube", side_effect=[self.object(kind="service"), b"{}", None]) as kube:
            self.task.remove("service", "-a")
        args, kwargs = kube.call_args_list[1]
        self.assertIn("/namespaces/confai-images/services/c8s-podacc-123-2-a", args[2])
        self.assertEqual(json.loads(kwargs["data"])["preconditions"], {"uid": "owned"})

    def test_all_vms_removed_before_dependencies_and_failures_retain_shared_disk(self):
        ledger = [{"kind": "pvc", "suffix": "-root", "uid": "disk"},
                  {"kind": "vm", "suffix": "-a", "uid": "a"}, {"kind": "vm", "suffix": "-b", "uid": "b"}]
        resources.write(self.task.ledger, ledger)
        with patch.object(self.task, "remove", side_effect=[RuntimeError("b still running"), None]) as remove:
            with self.assertRaises(RuntimeError):
                self.task.cleanup()
        self.assertEqual([call.args[:2] for call in remove.call_args_list], [("vm", "-b"), ("vm", "-a")])
        self.assertFalse(json.loads((self.task.evidence / "cleanup.json").read_text())["complete"])

    def test_interrupted_ledger_publication_preserves_previous_intent(self):
        self.intent()
        old = self.task.ledger.read_bytes()
        with patch.object(Path, "replace", side_effect=OSError("interrupted")):
            with self.assertRaises(OSError):
                resources.write(self.task.ledger, [])
        self.assertEqual(self.task.ledger.read_bytes(), old)
        self.assertFalse(list(self.task.private.glob("*.tmp")))

    def test_production_pin_rejects_mixed_sources_and_mutated_manifest(self):
        pins = json.loads((acceptance.FIXTURE / "production-image.json").read_text())
        bad = dict(pins, profileSource="0" * 40)
        with self.assertRaises(RuntimeError):
            acceptance.validate_pins(bad)
        for data in (b"{}", b"x" * 65537):
            with self.assertRaises(RuntimeError):
                acceptance.validate_manifest(data, pins)
        manifest = {"build": {"platform": "tdx"}, "inputs": {"base_image": {"sha256": pins["diskSHA256"]}},
                    "outputs": {"disk_image": {"sha256": pins["diskSHA256"]}}, "tdx": {k: "a" * 96 for k in ("mrtd", "rtmr1", "rtmr2")}}
        for change in ("valid", "disk", "platform", "rtmr2"):
            test = copy.deepcopy(manifest)
            if change == "disk": test["outputs"]["disk_image"]["sha256"] = "f" * 64
            if change == "platform": test["build"]["platform"] = "snp"
            if change == "rtmr2": test["tdx"]["rtmr2"] = ""
            raw = json.dumps(test).encode()
            pinned = dict(pins, manifestSHA256=hashlib.sha256(raw).hexdigest())
            if change == "valid":
                acceptance.validate_manifest(raw, pinned)
            else:
                with self.assertRaises(RuntimeError): acceptance.validate_manifest(raw, pinned)

    def test_rotation_requires_new_key_same_instance_and_named_identity(self):
        initial = {"sandboxID": "pcvm-a", "serial": "1", "spki": "old", "workload": "connected", "denied": True}
        self.assertFalse(acceptance.renewed(initial, dict(initial, serial="2")))
        self.assertFalse(acceptance.renewed(initial, dict(initial, spki="new")))
        self.assertTrue(acceptance.renewed(initial, dict(initial, serial="2", spki="new")))
        for change in ({"sandboxID": "pcvm-b"}, {"workload": ""}, {"denied": False}):
            with self.assertRaises(RuntimeError): acceptance.renewed(initial, dict(initial, **change))

    def test_early_rotation_that_persists_cannot_satisfy_timed_renewal(self):
        initial = {"sandboxID": "pcvm-a", "serial": "1", "spki": "first", "workload": "connected", "denied": True,
                   "notBefore": "2026-10-23T10:00:00Z", "notAfter": "2026-10-23T16:00:00Z"}
        early = dict(initial, serial="2", spki="early", notBefore="2026-10-23T10:01:00Z", notAfter="2026-10-23T16:01:00Z")
        self.assertFalse(acceptance.renewal_event(initial, early, 60))
        self.assertFalse(acceptance.renewal_event(initial, early, 3900))
        self.assertFalse(acceptance.renewal_event(early, early, 3900))
        timed = dict(initial, serial="3", spki="timed", notBefore="2026-10-23T10:55:00Z", notAfter="2026-10-23T16:55:00Z")
        self.assertTrue(acceptance.renewal_event(early, timed, 3300))
        self.assertFalse(acceptance.renewal_event(early, dict(timed, notAfter=early["notAfter"]), 3300))

    def test_receipt_requires_correct_uid_no_restart_and_zero_checker_exit(self):
        status = {"metadata": {"uid": "pod"}, "status": {"initContainerStatuses": [{"name": "c8s-mesh-endpoint", "ready": True, "restartCount": 0, "state": {"running": {"startedAt": "2026-10-23T10:00:00Z"}}}], "containerStatuses": [
            {"name": "app", "ready": True, "restartCount": 0, "state": {"running": {"startedAt": "2026-10-23T10:00:00Z"}}},
            {"name": "checker", "restartCount": 0, "state": {"terminated": {"exitCode": 0, "startedAt": "2026-10-23T10:00:00Z"}}}]}}
        self.assertTrue(acceptance.pod_state(status, "pod")["complete"])
        self.assertTrue(acceptance.pod_state(status, "pod")["ready"])
        with self.assertRaises(RuntimeError): acceptance.pod_state(status, "other")
        for change in ({"restartCount": 1}, {"state": {"terminated": {"exitCode": 0}}}):
            bad = copy.deepcopy(status)
            bad["status"]["initContainerStatuses"][0].update(change)
            with self.assertRaises(RuntimeError): acceptance.pod_state(bad, "pod")
        bad = copy.deepcopy(status)
        bad["status"]["initContainerStatuses"] = []
        with self.assertRaises(RuntimeError): acceptance.pod_state(bad, "pod")
        for index, key, value in [(0, "restartCount", 1), (0, "state", {"terminated": {"exitCode": 0}}),
                                   (1, "state", {"terminated": {"exitCode": 12}})]:
            bad = copy.deepcopy(status)
            bad["status"]["containerStatuses"][index][key] = value
            with self.assertRaises(RuntimeError): acceptance.pod_state(bad, "pod")

    def test_readiness_cycle_rejects_extra_outages(self):
        for trace in ([False, False, True, True, False, True], [True, False, False, True]):
            self.assertTrue(acceptance.readiness_cycle(trace))
        for trace in ([], [False, True], [True, False], [True, False, True, False, True]):
            self.assertFalse(acceptance.readiness_cycle(trace))

    def test_no_forward_authority_keeps_the_bounded_direct_warmup(self):
        task = acceptance.Acceptance(Path(self.temp.name), "123", "2", "confidential-dot-ai/C8s")
        task.identity = {"services": {"a": {"ip": "10.96.0.1"}}}
        with patch.object(task, "get"), patch.object(task, "instance"), patch.object(acceptance.socket, "create_connection", side_effect=OSError("booting")), patch.object(acceptance, "kube", side_effect=RuntimeError("can-i exits1")):
            task.connect("a", 8443)
        self.assertEqual(task.connections["a", 8443], "10.96.0.1:8443")
        self.assertEqual(task.forwards, [])

    def test_authenticated_reads_use_root_cli_commands(self):
        task = acceptance.Acceptance(Path(self.temp.name), "123", "2", "confidential-dot-ai/C8s")
        task.connections["a", 8443] = "127.0.0.1:12345"
        task.identity = {"expectedDigests": ["sha256:" + "a" * 64]}
        for mode in (["pod-attest"], ["pod-status", "get"]):
            with patch.object(acceptance, "command", return_value=b"{}") as command:
                task.cli_read("a", mode)
            argv = command.call_args.args[0]
            self.assertEqual(argv[1:1+len(mode)], mode)
            self.assertEqual("--expect-digest" in argv, mode == ["pod-attest"])
            self.assertNotIn("node", argv)

    def test_launch_secrets_use_only_required_bundle_files_without_disk_copy(self):
        task = acceptance.Acceptance(Path(self.temp.name), "123", "2", "confidential-dot-ai/C8s")
        expected = {}
        for side in acceptance.SIDES:
            directory = task.bundle / side / ("server" if side == "server" else "pod")
            directory.mkdir(parents=True)
            expected[side] = {name: (side + ":" + name + "\n").encode()
                              for name in ("pubkey", "launch.yaml", "launch.yaml.sig")}
            for name, data in expected[side].items():
                (directory / name).write_bytes(data)
            (directory / "operator.key").write_text("fixture excluded from guest inputs")
        before = {path.relative_to(task.root): path.read_bytes() for path in task.root.rglob("*") if path.is_file()}
        with patch.object(task, "create") as create:
            task.create_launch_secrets()
        self.assertEqual(create.call_count, 3)
        for call, side in zip(create.call_args_list, acceptance.SIDES):
            kind, suffix, spec = call.args
            self.assertEqual((kind, suffix, spec["kind"], spec["type"]), ("secret", "-" + side + "-opkey", "Secret", "Opaque"))
            self.assertEqual({name: base64.b64decode(data) for name, data in spec["data"].items()}, expected[side])
        after = {path.relative_to(task.root): path.read_bytes() for path in task.root.rglob("*") if path.is_file()}
        self.assertEqual(after, before)

    def test_incomplete_bundle_cannot_create_a_partial_secret(self):
        task = acceptance.Acceptance(Path(self.temp.name), "123", "2", "confidential-dot-ai/C8s")
        directory = task.bundle / "server/server"
        directory.mkdir(parents=True)
        for name in ("pubkey", "launch.yaml"):
            (directory / name).write_text("fixture")
        with patch.object(task, "create") as create, self.assertRaises(FileNotFoundError):
            task.create_launch_secrets()
        create.assert_not_called()

    def test_vm_shapes_share_readonly_root_but_only_server_has_scratch(self):
        task = acceptance.Acceptance(Path(self.temp.name), "123", "2", "confidential-dot-ai/C8s")
        for side in acceptance.SIDES:
            vm = task.vm(side)
            spec = vm["spec"]["template"]["spec"]
            self.assertEqual(vm["spec"]["runStrategy"], "Once")
            self.assertEqual(spec["domain"]["launchSecurity"], {"tdx": {}})
            disks = spec["domain"]["devices"]["disks"]
            self.assertTrue(disks[0]["disk"]["readonly"])
            self.assertEqual(spec["volumes"][0]["persistentVolumeClaim"]["claimName"], task.name + "-root")
            self.assertEqual(any(d.get("serial") == "confai-scratch" for d in disks), side == "server")


if __name__ == "__main__":
    unittest.main()
