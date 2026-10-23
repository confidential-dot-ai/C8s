#!/usr/bin/env python3
"""Local fixture checks; no Kubernetes access or public network calls."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    with mock.patch.object(sys, "argv", ["app.py", '{"podUID":"test"}']):
        spec.loader.exec_module(module)
    return module


app, stage = load("app"), load("stage")


def state(age, ready, healthy=True):
    return {"podUID": "test", "instance": "instance", "firstPass": 0, "elapsed": age, "checkedAt": age,
            "ready": ready, "checks": {str(i): {"ok": healthy} for i in range(6)}}


class FixtureTests(unittest.TestCase):
    def test_readiness_depends_on_network_and_has_observable_transitions(self):
        app.START = 0
        app.STATE = state(0, False)
        for now, want in ((119, False), (120, True), (299, True), (300, False), (479, False), (480, True)):
            app.STATE["checkedAt"] = now
            with self.subTest(now=now), mock.patch.object(app.time, "monotonic", return_value=now):
                self.assertEqual(app.report()["ready"], want)
        app.STATE["checks"]["0"]["ok"] = False
        with mock.patch.object(app.time, "monotonic", return_value=500):
            self.assertFalse(app.report()["ready"])

    def test_checker_does_not_accept_stale_success_after_soak(self):
        stale = state(3900, True)
        stale["checkedAt"] = 3000
        result, calls = self.run_checker([state(120, True), state(300, False), state(480, True), stale, state(3910, True)])
        self.assertEqual((result, calls), (0, 5))

    def run_checker(self, states):
        responses = []
        for value in states:
            response = mock.Mock(status=200)
            response.read.return_value = json.dumps(value).encode()
            connection = mock.Mock()
            connection.getresponse.return_value = response
            responses.append(connection)
        app.START = 0
        with mock.patch.object(app.http.client, "HTTPConnection", side_effect=responses) as factory, \
             mock.patch.object(app.time, "monotonic", return_value=0), \
             mock.patch.object(app.time, "sleep"), contextlib.redirect_stdout(io.StringIO()):
            result = app.checker()
        return result, factory.call_count

    def test_checker_waits_full_soak_and_does_not_accept_a_failed_final_check(self):
        result, calls = self.run_checker([state(120, True), state(300, False), state(480, True),
                                         state(3899, True), state(3900, False, False), state(3910, True)])
        self.assertEqual((result, calls), (0, 6))

    def test_checker_refuses_missing_negative_readiness_transition(self):
        result, _ = self.run_checker([state(120, True), state(480, True), state(700, True)])
        self.assertEqual(result, 11)

    def test_renderer_does_not_duplicate_cli_launch_payloads(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({"build": {"platform": "tdx"}, "tdx": {key: "a" * 96 for key in ("mrtd", "rtmr1", "rtmr2")}}))
            args = SimpleNamespace(name="acceptance-fixture", namespace="confai-images", manifest=manifest,
                                   manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest(),
                                   mesh_image="registry/mesh@sha256:" + "a" * 64, out=root / "bundle", cli="fixture-cli",
                                   collector_url="", source="a" * 40)
            endpoints = {side: {"ip": "10.43.0." + str(index + 10), "uid": side} for index, side in enumerate(("server", "a", "b"))}

            def cli(_cli, *values):
                if values[0] == "measurements":
                    return b'{"measurements":[{}]}'
                out = Path(values[values.index("--out") + 1])
                if values[0] == "keys":
                    Path(values[values.index("--pub-out") + 1]).write_text("fixture public key")
                else:
                    path = out / ("server" if values[2] == "new" else "pod")
                    path.mkdir(parents=True)
                    for name in ("pubkey", "launch.yaml", "launch.yaml.sig"):
                        (path / name).write_text("fixture " + name)
                return b""

            with mock.patch.object(stage, "allocated", return_value=endpoints), mock.patch.object(stage, "command", side_effect=cli), contextlib.redirect_stdout(io.StringIO()):
                stage.bundle(args)
            self.assertFalse((args.out / "opkey-secrets.json").exists())
            for side in ("server", "a", "b"):
                path = args.out / side / ("server" if side == "server" else "pod")
                self.assertEqual(sorted(p.name for p in path.iterdir()), ["launch.yaml", "launch.yaml.sig", "pubkey"])
            self.assertEqual(args.out.stat().st_mode & 0o777, 0o700)

    def test_service_addresses_can_be_allocated_before_a_vm_exists(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "services.json"
            args = SimpleNamespace(name="acceptance-test", namespace="confai-images", out=path, services=path)
            stage.services(args)
            body = json.loads(path.read_text())
            self.assertEqual(len(body["items"]), 3)
            for index, service in enumerate(body["items"]):
                self.assertNotIn("clusterIP", service["spec"])
                self.assertTrue(service["spec"]["publishNotReadyAddresses"])
                service["metadata"]["uid"] = "fixture-" + str(index)
                service["spec"]["clusterIP"] = "10.43.0." + str(index + 10)
            path.write_text(json.dumps(body))
            self.assertEqual(set(stage.allocated(args)), {"server", "a", "b"})
            for bad in ("169.254.1.1", "10.255.254.1", "10.53.0.4", "10.52.0.4", "10.0.2.2"):
                body["items"][0]["spec"]["clusterIP"] = bad
                path.write_text(json.dumps(body))
                with self.subTest(address=bad), self.assertRaises(ValueError):
                    stage.allocated(args)


if __name__ == "__main__":
    unittest.main()
