#!/usr/bin/env python3
"""Checks of the in-Pod workload; no Kubernetes access or public network calls."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    with mock.patch.object(sys, "argv", ["app.py", '{"podUID":"test"}']):
        spec.loader.exec_module(module)
    return module


app = load("app")


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


if __name__ == "__main__":
    unittest.main()
