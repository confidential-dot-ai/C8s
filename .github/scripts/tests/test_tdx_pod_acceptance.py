#!/usr/bin/env python3
"""Offline gates for the native hardware harness, not hardware substitutes."""
import base64
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
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

    def test_expected_mesh_name_matches_real_source_and_rejects_changed_contract(self):
        acceptance.validate_source_contract(SCRIPTS.parents[1])
        source = Path(self.temp.name) / "paired-source"
        path = source / "pkg/workloadclaims/workloadclaims.go"
        path.parent.mkdir(parents=True)
        for declaration in ('const MeshContainerName = "c8s-mesh-endpoint"', '',
                            'const MeshContainerName = "c8s-mesh"\nconst MeshContainerName = "another"'):
            path.write_text(declaration)
            with self.assertRaises(RuntimeError): acceptance.validate_source_contract(source)
        path.write_text('const MeshContainerName = "c8s-mesh"\n')
        acceptance.validate_source_contract(source)

    def test_receipt_requires_correct_uid_no_restart_and_zero_checker_exit(self):
        status = {"metadata": {"uid": "pod"}, "status": {"initContainerStatuses": [{"name": "c8s-mesh", "ready": True, "restartCount": 0, "state": {"running": {"startedAt": "2026-10-23T10:00:00Z"}}}], "containerStatuses": [
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

    def test_authenticated_reads_use_root_cli_commands_and_keep_exact_gate(self):
        task = acceptance.Acceptance(Path(self.temp.name), "123", "2", "confidential-dot-ai/C8s")
        task.connections["a", 8443] = "127.0.0.1:12345"
        task.identity = {"expectedDigests": ["sha256:" + "a" * 64]}
        result = subprocess.CompletedProcess([], 0, stdout=b"{}", stderr=b"")
        with patch.object(acceptance.subprocess, "run", return_value=result) as run, contextlib.redirect_stdout(io.StringIO()):
            task.cli_read("a", ["pod-attest"])
            task.cli_read("a", ["pod-status", "get"])
            task.cli_read("a", ["pod-attest"], exact_digests=False)
        exact, status, observed = [call.args[0] for call in run.call_args_list]
        self.assertEqual(exact[1], "pod-attest")
        self.assertEqual(status[1:3], ["pod-status", "get"])
        self.assertNotIn("node", exact)
        self.assertIn("--expect-digest", exact)
        self.assertNotIn("--expect-digest", observed)
        self.assertEqual(exact[:exact.index("--expect-digest")], observed)
        task.identity["expectedDigests"] = []
        with self.assertRaises(RuntimeError): task.cli_read("a", ["pod-attest"])

    def test_read_wrapper_rejects_mutations_and_private_key_flags(self):
        task = acceptance.Acceptance(Path(self.temp.name), "123", "2", "confidential-dot-ai/C8s")
        with patch.object(acceptance.subprocess, "run") as run:
            for phase, side, options in [("secrets-put", "server", []), ("cds-ca", "server", ["--operator-key", "private.key"]),
                                          ("pod-status", "a", ["--insecure", "true"]), ("pod-attest", "server", [])]:
                with self.assertRaises(RuntimeError): task.read_only_cli(phase, side, options)
        run.assert_not_called()

    def test_read_errors_expose_bounded_stderr_without_argv_stdout_or_private_path(self):
        task = acceptance.Acceptance(Path(self.temp.name), "123", "2", "confidential-dot-ai/C8s")
        stderr = b"x" * 5000 + str(task.private).encode() + b"/manifest.json: digest mismatch\x1b"
        result = subprocess.CompletedProcess([], 1, stdout=b"not-for-logs", stderr=stderr)
        output = io.StringIO()
        with patch.object(acceptance.subprocess, "run", return_value=result) as run, patch.dict(acceptance.os.environ, {"C8S_OPERATOR_KEY": "not-for-child"}), contextlib.redirect_stdout(output):
            with self.assertRaises(RuntimeError): task.read_only_cli("pod-attest", "a", ["--node", "argv-not-for-logs"])
        self.assertNotIn("C8S_OPERATOR_KEY", run.call_args.kwargs["env"])
        self.assertEqual(run.call_args.kwargs["stdin"], subprocess.DEVNULL)
        record = json.loads((task.evidence / "a-pod-attest-last-error.json").read_text())
        self.assertLessEqual(len(record["error"]), 4096)
        self.assertIn("digest mismatch", record["error"])
        self.assertEqual((record["phase"], record["side"]), ("pod-attest", "a"))
        self.assertIn("timestamp", record)
        for forbidden in ("argv-not-for-logs", "not-for-logs", str(task.private), "\x1b"):
            self.assertNotIn(forbidden, output.getvalue())

    def test_read_timeout_does_not_stringify_the_command(self):
        task = acceptance.Acceptance(Path(self.temp.name), "123", "2", "confidential-dot-ai/C8s")
        timeout = subprocess.TimeoutExpired(["argv-not-for-logs"], 1, output=b"stdout-not-for-logs", stderr=b"context deadline")
        with patch.object(acceptance.subprocess, "run", side_effect=timeout), contextlib.redirect_stdout(io.StringIO()) as output:
            with self.assertRaisesRegex(RuntimeError, "context deadline"):
                task.read_only_cli("pod-status", "b", [])
        self.assertNotIn("argv-not-for-logs", output.getvalue())
        self.assertNotIn("stdout-not-for-logs", output.getvalue())

    def test_mesh_probe_uses_owned_binary_known_mode_and_bounded_diagnostics(self):
        task = acceptance.Acceptance(Path(self.temp.name), "123", "2", "confidential-dot-ai/C8s")
        task.connections["a", 8080] = "127.0.0.1:12345"
        result = subprocess.CompletedProcess([], 1, stdout=b"", stderr=b"peer certificate signature invalid")
        with patch.object(acceptance.subprocess, "run", return_value=result) as run, contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError, "signature invalid"): task.leaf("a", "certless")
            self.assertEqual(run.call_args.args[0][0], str(task.probe))
            self.assertEqual(run.call_args.kwargs["timeout"], 15)
            self.assertEqual(run.call_args.kwargs["stdin"], subprocess.DEVNULL)
            run.reset_mock()
            with self.assertRaises(RuntimeError): task.leaf("a", "unknown-mode")
            run.assert_not_called()
        record = json.loads((task.evidence / "a-pod-mesh-last-error.json").read_text())
        self.assertIn("signature invalid", record["error"])
        self.assertEqual((record["side"], record["phase"]), ("a", "pod-mesh"))

    def test_mutation_command_errors_still_hide_payload_and_stderr(self):
        result = subprocess.CompletedProcess([], 1, stdout=b"", stderr=b"payload-not-for-logs")
        with patch.object(resources.subprocess, "run", return_value=result):
            with self.assertRaises(RuntimeError) as error:
                resources.command(["kubectl", "create"], data=b"stdin-not-for-logs")
        self.assertNotIn("payload-not-for-logs", str(error.exception))
        self.assertNotIn("stdin-not-for-logs", str(error.exception))

    def test_warmup_saves_status_and_diagnostic_attestation_without_bypassing_gate(self):
        task = acceptance.Acceptance(Path(self.temp.name), "123", "2", "confidential-dot-ai/C8s")
        calls = []
        def read(side, mode, deadline, **kwargs):
            calls.append((side, mode, kwargs))
            if side == "a" and mode == ["pod-attest"] and kwargs.get("exact_digests", True):
                raise RuntimeError("measured digest mismatch")
            return {"side": side, "mode": mode, "measured_digests": ["observed"]}
        state = {"ready": True, "running": True}
        traces, states = {"a": [], "b": []}, {}
        with patch.object(task, "ca"), patch.object(task, "cli_read", side_effect=read), patch.object(acceptance, "pod_state", return_value=state), patch.object(task, "leaf", return_value={"workload": "connected"}), contextlib.redirect_stdout(io.StringIO()):
            initial, statuses = task.warmup_round(None, traces, states)
        self.assertEqual(set(initial), {"b"})
        self.assertEqual(statuses, {"b": json.loads((task.evidence / "b-initial-status.json").read_text())})
        self.assertEqual(calls[0][:2], ("a", ["pod-status", "get"]))
        self.assertEqual(calls[3][:2], ("b", ["pod-status", "get"]))
        self.assertTrue((task.evidence / "a-initial-status.json").exists())
        self.assertFalse((task.evidence / "a-initial-attestation.json").exists())
        diagnostic = json.loads((task.evidence / "a-diagnostic-attestation.json").read_text())
        self.assertTrue(diagnostic["diagnosticOnly"])
        self.assertFalse(diagnostic["exactDigestGatePassed"])
        self.assertEqual(diagnostic["report"]["measured_digests"], ["observed"])
        self.assertTrue((task.evidence / "b-initial-attestation.json").exists())

    def test_cds_and_first_pod_failures_do_not_hide_other_pod_observations(self):
        task = acceptance.Acceptance(Path(self.temp.name), "123", "2", "confidential-dot-ai/C8s")
        calls = []
        def read(side, mode, deadline, **kwargs):
            calls.append((side, mode))
            if side == "a": raise RuntimeError("guest unavailable")
            return {"side": side}
        with patch.object(task, "ca", side_effect=RuntimeError("CDS unavailable")), patch.object(task, "cli_read", side_effect=read), patch.object(acceptance, "pod_state", return_value={"ready": False, "running": True}), contextlib.redirect_stdout(io.StringIO()):
            initial, statuses = task.warmup_round(None, {"a": [], "b": []}, {})
        self.assertEqual((initial, statuses), ({}, {}))
        self.assertIn(("b", ["pod-status", "get"]), calls)
        self.assertIn(("b", ["pod-attest"]), calls)
        self.assertTrue((task.evidence / "server-cds-ca-last-error.json").exists())
        self.assertTrue((task.evidence / "a-pod-attest-last-error.json").exists())
        self.assertTrue((task.evidence / "b-initial-status.json").exists())

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


def readiness_status(condition="True", timestamp="2026-01-01T00:10:00Z", *, uid="pod", complete=False, ready=True):
    def container(name):
        return {"name": name, "ready": ready if name == "app" else True, "restartCount": 0,
                "state": {"running": {"startedAt": "2026-01-01T00:00:00Z"}}}
    app, checker, mesh = [container(name) for name in ("app", "checker", acceptance.MESH_CONTAINER_NAME)]
    if complete:
        checker.update(ready=False, state={"terminated": {"exitCode": 0,
                       "startedAt": "2026-01-01T00:00:00Z", "finishedAt": timestamp}})
    return {"metadata": {"uid": uid}, "status": {
        "conditions": [{"type": "Ready", "status": condition, "lastTransitionTime": timestamp}],
        "containerStatuses": [app, checker], "initContainerStatuses": [mesh]}}


class ReadinessTests(unittest.TestCase):
    def tracker(self, status=None, recovered=True):
        status = status or readiness_status()
        parsed = acceptance.pod_state(status, status["metadata"]["uid"])
        tracker = acceptance.ReadinessConditions(status["metadata"]["uid"], parsed["starts"])
        self.assertTrue(tracker.observe(status, parsed, recovered)["accepted"])
        return tracker

    def observation(self, tracker, status, recovered=True):
        return tracker.observe(status, acceptance.pod_state(status, status["metadata"]["uid"]), recovered)

    def test_expected_cycle_and_stable_samples_pass(self):
        tracker = self.tracker(readiness_status("False", "2026-01-01T00:00:00Z", ready=False), False)
        traces = [False]
        for condition, minute in (("False", 0), ("True", 2), ("True", 2), ("False", 5), ("True", 8), ("True", 8)):
            status = readiness_status(condition, f"2026-01-01T00:{minute:02}:00Z", ready=condition == "True")
            traces.append(condition == "True")
            self.assertTrue(self.observation(tracker, status, acceptance.readiness_cycle(traces))["accepted"])
        self.assertTrue(tracker.recovered)

    def test_hidden_true_transition_is_rejected_before_and_after_recovery(self):
        for recovered in (False, True):
            with self.subTest(recovered=recovered):
                tracker = self.tracker(recovered=recovered)
                verdict = self.observation(tracker, readiness_status(timestamp="2026-01-01T00:11:00Z"), recovered)
                self.assertFalse(verdict["accepted"])
                self.assertIn("between True samples", verdict["failure"])
                self.assertEqual(verdict["previous"]["status"], verdict["current"]["status"])

    def test_successful_checker_withdrawal_may_be_delayed_but_is_allowed_only_once(self):
        for delayed in (False, True):
            with self.subTest(delayed=delayed):
                tracker = self.tracker()
                if delayed:
                    self.assertTrue(self.observation(tracker, readiness_status(complete=True))["accepted"])
                ended = readiness_status("False", "2026-01-01T01:10:00Z", complete=True)
                verdict = self.observation(tracker, ended)
                self.assertTrue(verdict["accepted"])
                self.assertTrue(verdict["checkerCompletionWithdrawal"])
                self.assertTrue(self.observation(tracker, ended)["accepted"])
                for condition in ("False", "True", "Unknown"):
                    extra = readiness_status(condition, "2026-01-01T01:11:00Z", complete=True)
                    self.assertFalse(self.observation(tracker, extra)["accepted"])

    def test_completion_cannot_hide_app_or_mesh_failure(self):
        for complete in (False, True):
            for failed in ("app", "mesh", "condition"):
                with self.subTest(complete=complete, failed=failed):
                    status = readiness_status("False", "2026-01-01T01:10:00Z", complete=complete)
                    if failed == "app": status["status"]["containerStatuses"][0]["ready"] = False
                    if failed == "mesh": status["status"]["initContainerStatuses"][0]["ready"] = False
                    if failed == "condition" and complete: continue
                    self.assertFalse(self.observation(self.tracker(), status)["accepted"])

    def test_conditions_and_identity_fail_closed(self):
        baseline = readiness_status()
        bad = []
        for value in (None, [], [None], baseline["status"]["conditions"] * 2):
            status = copy.deepcopy(baseline)
            status["status"]["conditions"] = value
            bad.append(status)
        for key, value in (("type", "ContainersReady"), ("status", True), ("status", "invalid"),
                           ("lastTransitionTime", None), ("lastTransitionTime", "invalid"),
                           ("lastTransitionTime", "2026-13-01T00:10:00Z"),
                           ("lastTransitionTime", "2026-01-01T00:10:00+00:00"),
                           ("lastTransitionTime", "2026-01-01T00:09:00Z")):
            status = copy.deepcopy(baseline)
            status["status"]["conditions"][0][key] = value
            bad.append(status)
        status = copy.deepcopy(baseline)
        status["metadata"]["uid"] = "another-pod"
        bad.append(status)
        for key in ("containerStatuses", "initContainerStatuses"):
            status = copy.deepcopy(baseline)
            status["status"][key][0]["state"]["running"]["startedAt"] = "2026-01-01T00:01:00Z"
            bad.append(status)
        for status in bad:
            with self.subTest(status=status):
                self.assertFalse(self.observation(self.tracker(), status)["accepted"])

    def test_failed_verdict_is_saved_privately_before_raising(self):
        with tempfile.TemporaryDirectory() as directory:
            task = acceptance.Acceptance(Path(directory), "123", "2", "confidential-dot-ai/C8s")
            status = readiness_status(timestamp="2026-01-01T00:11:00Z")
            with self.assertRaisesRegex(RuntimeError, "between True samples"):
                task.record_readiness(self.tracker(), status, acceptance.pod_state(status, "pod"), True, "rejected")
            path = task.evidence / "rejected.json"
            record = json.loads(path.read_text())
            self.assertEqual(record["status"], status)
            self.assertFalse(record["observation"]["accepted"])
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_observer_saves_readiness_before_rejection_or_leaf_failure(self):
        for hidden in (False, True):
            with self.subTest(hidden=hidden), tempfile.TemporaryDirectory() as directory:
                task = acceptance.Acceptance(Path(directory), "123", "2", "confidential-dot-ai/C8s")
                task.run_deadline = 10000
                resources.write(task.evidence / "mesh-ca.pem", b"public CA")
                baseline = readiness_status(uid=task.name)
                observed = readiness_status(uid=task.name, timestamp="2026-01-01T00:11:00Z" if hidden else "2026-01-01T00:10:00Z")
                def warmup(deadline, traces, states):
                    for side in ("a", "b"):
                        traces[side].extend([True, False, True])
                        states[side] = acceptance.pod_state(baseline, task.name)
                    return ({side: {"sandboxID": side} for side in ("a", "b")}, {side: baseline for side in ("a", "b")})
                with patch.object(task, "connect"), patch.object(task, "instance"), patch.object(task, "warmup_round", side_effect=warmup), \
                     patch.object(task, "cli_read", return_value=observed), patch.object(task, "leaf", side_effect=RuntimeError("leaf unavailable")) as leaf, \
                     patch.object(acceptance.time, "monotonic", return_value=100), contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaisesRegex(RuntimeError, "between True samples" if hidden else "leaf unavailable"):
                        task.observe()
                record = json.loads((task.evidence / "readiness-001-a.json").read_text())
                self.assertEqual(record["status"], observed)
                self.assertEqual(record["observation"]["accepted"], not hidden)
                self.assertEqual(leaf.call_count, 0 if hidden else 1)
                self.assertFalse((task.evidence / "result.json").exists())

    def test_post_negative_timestamp_change_cannot_satisfy_acceptance(self):
        for extra in (False, True):
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as directory:
                task = acceptance.Acceptance(Path(directory), "123", "2", "confidential-dot-ai/C8s")
                task.run_deadline = 10000
                resources.write(task.evidence / "mesh-ca.pem", b"public CA")
                baseline = readiness_status(uid=task.name)
                completed = readiness_status("False", "2026-01-01T01:10:00Z", uid=task.name, complete=True)
                final = readiness_status("False", "2026-01-01T01:11:00Z", uid=task.name, complete=True) if extra else completed
                reads = iter([baseline, baseline, completed, completed, final, final])
                clock = [0]
                def warmup(deadline, traces, states):
                    for side in ("a", "b"):
                        traces[side].extend([True, False, True])
                        states[side] = acceptance.pod_state(baseline, task.name)
                    return ({side: {"sandboxID": side} for side in ("a", "b")}, {side: baseline for side in ("a", "b")})
                def read(side, mode, deadline):
                    return next(reads) if mode == ["pod-status", "get"] else {}
                def pause(deadline, seconds):
                    clock[0] += seconds
                with patch.object(task, "connect"), patch.object(task, "instance"), patch.object(task, "warmup_round", side_effect=warmup), \
                     patch.object(task, "cli_read", side_effect=read), patch.object(task, "leaf", return_value={}), \
                     patch.object(task, "ca", side_effect=lambda path, deadline: resources.write(path, b"public CA")), \
                     patch.object(acceptance, "renewal_event", return_value=True), patch.object(acceptance, "SOAK", 0), \
                     patch.object(acceptance, "pause", side_effect=pause), patch.object(acceptance.time, "monotonic", side_effect=lambda: clock[0]), \
                     contextlib.redirect_stdout(io.StringIO()):
                    if extra:
                        with self.assertRaisesRegex(RuntimeError, "transition after recovery"): task.observe()
                    else:
                        task.observe()
                self.assertEqual((task.evidence / "result.json").exists(), not extra)
                record = json.loads((task.evidence / "readiness-final-a.json").read_text())
                self.assertEqual(record["status"], final)
                self.assertEqual(record["observation"]["accepted"], not extra)


if __name__ == "__main__":
    unittest.main()
