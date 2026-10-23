#!/usr/bin/env python3
"""Development-console isolation, ownership, confidentiality and bound checks."""
import base64
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location("runtime_diagnostic", SCRIPTS / "tdx-pod-runtime-diagnostic.py")
diagnostic = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diagnostic)
MARKER = "a" * 32


def transcript(extra=()):
    records = list(extra) + [{"kind": "command", "name": name, "exit": 0}
                            for name in ("units", "journal", "sandboxes", "containers", "plugins")]
    return ("unframed private boot data\r\n__C8S_" + MARKER + "_BEGIN__\r\n" +
            "\r\n".join(json.dumps(record) for record in records) + "\r\n__C8S_" + MARKER + "_END__\r\n").encode()


class DiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.production = json.loads((diagnostic.acceptance.FIXTURE / "production-image.json").read_text())
        self.pins = dict(self.production, diagnosticOnly=True, developmentProfile=True, runtimeWrapper=diagnostic.WRAPPER)
        self.task = diagnostic.RuntimeDiagnostic(Path(self.temp.name), "123", "1", "confidential-dot-ai/C8s", pins=self.pins)

    def test_dev_and_production_pins_are_mutually_exclusive(self):
        diagnostic.acceptance.validate_pins(self.production)
        diagnostic.validate_diagnostic_pins(self.pins)
        with self.assertRaises(RuntimeError): diagnostic.acceptance.validate_pins(self.pins)
        with self.assertRaises(RuntimeError): diagnostic.validate_diagnostic_pins(self.production)
        for field, value in (("diagnosticOnly", False), ("developmentProfile", False), ("runtimeWrapper", "enabled"), ("profileSource", "f" * 40)):
            bad = dict(self.pins, **{field: value})
            with self.assertRaises(RuntimeError): diagnostic.validate_diagnostic_pins(bad)
        # False flags must not turn the production validator into a dev pin selector.
        with self.assertRaises(RuntimeError): diagnostic.acceptance.validate_pins(dict(self.production, diagnosticOnly=False))

    def test_console_authority_uses_exact_attributes_and_fails_closed(self):
        response = {"status": {"allowed": True, "reason": "existing scoped role"}}
        with patch.object(diagnostic, "kube", return_value=response) as kube:
            self.task.check_console_authority()
        self.assertEqual(kube.call_args.args, ("create", "--raw", "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", "-f", "-"))
        request = json.loads(kube.call_args.kwargs["data"])
        self.assertEqual(request["spec"]["resourceAttributes"], {"namespace": "confai-images", "verb": "get", "group": "subresources.kubevirt.io", "resource": "virtualmachineinstances", "subresource": "console"})
        for status in ({"allowed": False, "denied": True, "reason": "existing role denies console", "evaluationError": "x" * 2000},
                       {"allowed": False, "reason": "token=canary"}, {"allowed": True, "denied": True},
                       {}, {"allowed": "true"}, {"allowed": True, "denied": "false"}, None):
            with patch.object(diagnostic, "kube", return_value={"status": status}):
                with self.assertRaises(RuntimeError): self.task.check_console_authority()
            report = (self.task.evidence / "console-authority.json").read_text()
            self.assertNotIn("canary", report)
            self.assertLessEqual(len(json.loads(report).get("evaluationError", "")), 1024)
        with patch.object(diagnostic, "kube", side_effect=RuntimeError("command failed: kubectl (exit 1)")):
            with self.assertRaises(RuntimeError): self.task.check_console_authority()

    def test_projection_drops_secrets_noise_and_unrequested_fields(self):
        unit = diagnostic.UNITS[1]
        safe = {"kind": "journal", "unit": unit, "time": "1", "message": "NRI denied unapproved image"}
        candidates = [safe, dict(safe, message="Authorization: Bearer canary"),
                      dict(safe, message="-----BEGIN PRIVATE KEY-----canary"),
                      dict(safe, message="environment: canary"), dict(safe, unit="unrelated.service"),
                      dict(safe, env="canary"), {"kind": "container", "env": "canary"}]
        result = diagnostic.public_records(transcript(candidates), MARKER)
        self.assertIn(safe, result["records"])
        self.assertEqual(result["omittedRecords"], 6)
        self.assertNotIn("canary", json.dumps(result))
        self.assertNotIn("private boot", json.dumps(result))
        for raw in (transcript().replace(b"_END__", b"_BAD__"), transcript() + transcript(), b"x" * (diagnostic.MAX_TRANSCRIPT + 1)):
            with self.assertRaises(RuntimeError): diagnostic.public_records(raw, MARKER)

    def test_journal_filters_late_secret_marker_before_truncation(self):
        for message, exposed in (("early canary " + "x" * 1700 + " Authorization: Bearer confidential", False),
                                 ("ordinary runtime failure " + "x" * 1700, True)):
            record = {"_SYSTEMD_UNIT": diagnostic.UNITS[0], "__REALTIME_TIMESTAMP": "1", "MESSAGE": message}
            result = subprocess.run(["jq", "-c", diagnostic.JOURNAL_PROJECTION], input=json.dumps(record).encode(), capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            if exposed:
                self.assertEqual(len(json.loads(result.stdout)["message"]), 1536)
            else:
                self.assertEqual(result.stdout, b"")

    def test_payload_has_fixed_read_only_projection_and_valid_shell(self):
        payload = diagnostic.console_payload(MARKER)
        self.assertEqual(subprocess.run(["bash", "-n"], input=payload.encode(), capture_output=True).returncode, 0)
        for forbidden in (" inspect", "cat /", "kubectl", "/etc/confai", "launch.yaml", "systemctl restart", "printenv"):
            self.assertNotIn(forbidden, payload)
        self.assertIn("--runtime-endpoint unix:///run/k3s/containerd/containerd.sock", payload)
        self.assertIn("-n 160", payload)
        self.assertLess(len(base64.b64encode(payload.encode())) + 45, 3500)
        with self.assertRaises(RuntimeError): diagnostic.console_payload("; echo arbitrary")

    def test_static_failures_are_useful_but_process_details_stay_private(self):
        self.assertEqual(diagnostic.public_failure(RuntimeError("console driver exit 13"))["error"], "console driver exit 13")
        self.assertEqual(diagnostic.public_failure(RuntimeError("missing scoped VMI console authority"))["error"], "missing scoped VMI console authority")
        for error in (RuntimeError("private argv canary"), subprocess.TimeoutExpired(["tool", "canary"], 5), OSError("private canary")):
            self.assertNotIn("canary", json.dumps(diagnostic.public_failure(error)))

    def test_expect_pty_delivers_payload_and_receives_complete_frame(self):
        # A local console surrogate exercises expect itself; it never invokes guest commands.
        binary = Path(self.temp.name) / "virtctl"
        binary.write_text("#!" + sys.executable + "\nimport os,sys\nprint('Successfully connected',flush=True)\nsys.stdin.readline()\nprint('root# ',end='',flush=True)\nsys.stdin.readline()\nprint('\\n'+os.environ['C8S_DIAG_END'],flush=True)\nsys.stdin.read(1)\n")
        binary.chmod(0o700)
        script = Path(self.temp.name) / "console.exp"
        script.write_text(diagnostic.EXPECT)
        env = {"PATH": self.temp.name + os.pathsep + os.environ["PATH"], "TERM": "dumb", "C8S_DIAG_KUBECONFIG": "/unused", "C8S_DIAG_NS": "confai-images", "C8S_DIAG_VM": "owned", "C8S_DIAG_COMMAND": "fixed command", "C8S_DIAG_END": "__C8S_"+MARKER+"_END__"}
        raw, error = diagnostic.bounded_process(["expect", str(script)], env, time.monotonic() + 5)
        self.assertIsNone(error, raw.decode(errors="replace"))
        self.assertIn(env["C8S_DIAG_END"].encode(), raw)

    def test_console_subprocess_is_byte_and_time_bounded(self):
        env = {"PATH": os.environ["PATH"]}
        raw, error = diagnostic.bounded_process([sys.executable, "-c", "import sys; sys.stdout.write('x'*500000); sys.stdout.flush()"], env, time.monotonic() + 5)
        self.assertEqual(len(raw), diagnostic.MAX_TRANSCRIPT)
        self.assertEqual(error, "console output exceeded byte limit")
        start = time.monotonic()
        raw, error = diagnostic.bounded_process([sys.executable, "-c", "import time; time.sleep(5)"], env, start + .1)
        self.assertEqual(error, "console timed out")
        self.assertLess(time.monotonic() - start, 4)

    def test_console_checks_identity_before_and_after_and_keeps_raw_private(self):
        owned = {"metadata": {"uid": "owned"}, "status": {"phase": "Running"}}
        with patch.object(self.task, "instance", side_effect=RuntimeError("ownership mismatch")), patch.object(diagnostic, "bounded_process") as process:
            with self.assertRaises(RuntimeError): self.task.console("a")
            process.assert_not_called()
        for after, success in ((dict(owned, metadata={"uid": "replacement"}), False), (owned, True)):
            with patch.object(self.task, "instance", side_effect=[owned, after]) as instance, patch.object(diagnostic.uuid, "uuid4") as nonce, patch.object(diagnostic, "bounded_process", return_value=(transcript(), None)) as process:
                nonce.return_value.hex = MARKER
                if success:
                    report = self.task.console("a")
                    self.assertTrue(report["diagnosticOnly"])
                    self.assertFalse(report["productionAcceptance"])
                else:
                    with self.assertRaises(RuntimeError): self.task.console("a")
                    self.assertFalse((self.task.evidence / "a-runtime.json").exists())
                self.assertEqual(instance.call_count, 2)
                env = process.call_args.args[1]
                self.assertEqual(set(env), {"PATH", "TERM", "C8S_DIAG_NS", "C8S_DIAG_VM", "C8S_DIAG_KUBECONFIG", "C8S_DIAG_COMMAND", "C8S_DIAG_END"})
                self.assertTrue((self.task.private / "a-console.raw").exists())
                self.assertFalse((self.task.evidence / "a-console.raw").exists())

    def test_diagnostic_cannot_enter_acceptance_or_publish_raw_capture_even_on_failure(self):
        for failure in (None, RuntimeError("private process argv canary")):
            with patch.object(self.task, "prepare"), patch.object(self.task, "provision"), patch.object(self.task, "diagnose", side_effect=failure), patch.object(self.task, "stop_forwards") as stop, patch.object(diagnostic.acceptance.Acceptance, "observe", side_effect=AssertionError("acceptance entered")), patch.object(diagnostic.acceptance.Acceptance, "capture", side_effect=AssertionError("raw capture entered")), contextlib.redirect_stdout(io.StringIO()):
                if failure:
                    with self.assertRaisesRegex(RuntimeError, "development runtime diagnostic failed"):
                        diagnostic.run(self.task)
                else:
                    diagnostic.run(self.task)
                stop.assert_called_once()
            for path in self.task.evidence.glob("*"):
                text = path.read_text()
                self.assertNotIn("canary", text)
                self.assertNotIn('"passed": true', text)

    def test_console_failure_on_a_does_not_skip_b(self):
        with patch.object(self.task, "connect"), patch.object(self.task, "ca"), patch.object(self.task, "cli_read", return_value={}), patch.object(diagnostic, "pause"), patch.object(self.task, "console", side_effect=[RuntimeError("private canary"), {}]) as console, contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError, "capture incomplete"):
                self.task.diagnose()
        self.assertEqual([call.args[0] for call in console.call_args_list], ["a", "b"])
        receipt = (self.task.evidence / "result.json").read_text()
        self.assertNotIn("canary", receipt)
        self.assertFalse(json.loads(receipt)["captureComplete"])


if __name__ == "__main__":
    unittest.main()
