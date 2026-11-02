"""Execute the embedded guest probe with deterministic time and no network."""
from contextlib import nullcontext
import errno
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[3] / "internal/podprovider/cloud_cds_workload_integration_linux_test.go"


class ProbeExit(Exception):
    def __init__(self, code):
        self.code = code


class GuestProbeTests(unittest.TestCase):
    def run_probe(self, reachable, renewal=True):
        script = SOURCE.read_text().split("const cloudCDSScript = `", 1)[1].split("`", 1)[0]
        now, paths, observer, transitions, withdrawn = [0], set(), [], [], []
        scope = {}
        ready = [False]

        def response(path):
            handler = object.__new__(scope["Handler"])
            codes = []
            handler.path = path
            handler.send_response = codes.append
            handler.end_headers = lambda: None
            handler.do_GET()
            return codes[0]

        def set_ready(value):
            if ready[0] != value:
                transitions.append((now[0], value))
                ready[0] = value
                if not value:
                    withdrawn.append((response("/ready"), response("/live")))

        def connect(address, timeout):
            self.assertEqual(address, ("203.0.113.5", 8443))
            self.assertEqual(timeout, 2)
            result = reachable(now[0])
            if result is True:
                return nullcontext()
            number = errno.ECONNREFUSED if result is False else result
            raise OSError(number, "isolated probe transport failure")

        def sleep(seconds):
            now[0] += seconds

        def create(path, _flags, mode):
            self.assertIn(path, ("/restart/.writable", "/restart/once"))
            self.assertEqual(mode, 0o600)
            if path in paths:
                raise FileExistsError(errno.EEXIST, path)
            paths.add(path)
            return 3

        def exit_process(code):
            raise ProbeExit(code)

        modules = {
            "os": SimpleNamespace(open=create, close=lambda _fd: None,
                unlink=paths.remove, path=SimpleNamespace(exists=lambda path: path in paths),
                O_CREAT=os.O_CREAT, O_EXCL=os.O_EXCL, O_WRONLY=os.O_WRONLY,
                _exit=exit_process),
            "time": SimpleNamespace(monotonic=lambda: now[0], sleep=sleep),
            "socket": SimpleNamespace(create_connection=connect),
            "threading": SimpleNamespace(
                Event=lambda: SimpleNamespace(set=lambda: set_ready(True),
                    clear=lambda: set_ready(False), is_set=lambda: ready[0]),
                Thread=lambda target, daemon: SimpleNamespace(start=lambda: observer.append(target))),
            "http.server": SimpleNamespace(BaseHTTPRequestHandler=object,
                HTTPServer=lambda *_args: SimpleNamespace(serve_forever=lambda: None)),
        }
        args = ["probe.py", "203.0.113.5"] + (["3900"] if renewal else [])
        exit_code = None
        with patch.dict(sys.modules, modules), patch.object(sys, "argv", args):
            exec(compile(script, str(SOURCE), "exec"), scope)
            self.assertEqual(len(observer), 1)
            try:
                observer[0]()
            except ProbeExit as error:
                exit_code = error.code
        return SimpleNamespace(exit=exit_code, transitions=transitions,
            paths=paths, withdrawn=withdrawn, elapsed=now[0])

    def test_renewal_withdraws_readiness_then_recovers_without_exit(self):
        proof = self.run_probe(lambda t: t < 2 or t >= 3910)
        self.assertIsNone(proof.exit)
        self.assertEqual(proof.transitions, [(0, True), (3902, False), (3910, True)])
        self.assertEqual(proof.withdrawn, [(503, 200)])
        self.assertEqual(proof.paths, set())

    def test_reachability_resets_the_continuous_outage(self):
        proof = self.run_probe(lambda t: t < 2 or 500 <= t < 502 or t >= 4410)
        self.assertIsNone(proof.exit)
        self.assertEqual(proof.transitions, [(0, True), (4402, False), (4410, True)])
        self.assertEqual(proof.paths, set())

    def test_initial_unreachability_cannot_confirm_an_outage(self):
        proof = self.run_probe(lambda _t: False)
        self.assertEqual(proof.exit, 45)
        self.assertEqual(proof.elapsed, 60)
        self.assertEqual(proof.transitions, [])

    def test_nontransport_failure_cannot_confirm_an_outage(self):
        proof = self.run_probe(lambda t: True if t < 2 else errno.EACCES)
        self.assertEqual(proof.exit, 43)
        self.assertEqual(proof.transitions, [(0, True)])

    def test_no_outage_hits_the_bounded_deadline(self):
        proof = self.run_probe(lambda _t: True)
        self.assertEqual(proof.exit, 46)
        self.assertEqual(proof.elapsed, 4800)
        self.assertEqual(proof.transitions, [(0, True)])

    def test_short_outage_still_exits_once_after_two_minutes(self):
        proof = self.run_probe(lambda t: t < 2, renewal=False)
        self.assertEqual(proof.exit, 0)
        self.assertEqual(proof.elapsed, 122)
        self.assertEqual(proof.transitions, [(0, True)])
        self.assertEqual(proof.paths, {"/restart/once"})


if __name__ == "__main__":
    unittest.main()
