import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'cds-ha-metadata'))
import run


class PhaseDispatch(unittest.TestCase):
    def attempt(self, codes, *, premature_receipt=False, operation='prepare'):
        runner = object.__new__(run.Run)
        runner.live = runner.save = runner.current = runner.ensure_consoles = Mock()
        runner.guests = {0: {}}; runner.state = {'phases': []}
        runner.args = SimpleNamespace(client='frozen-client', backend='raft')
        process = Mock(); process.poll.return_value = None
        runner.tunnels = {0: (process, 'https://127.0.0.1:1001')}
        endpoints = []; notices = []; restarts = []
        runner.event = lambda name, **fields: notices.append((name, fields))
        def restart(slot):
            restarts.append(slot)
            runner.tunnels[slot] = (process, 'https://127.0.0.1:1002')
        runner.open_tunnel = restart
        runner.atomic = lambda path, value: path.write_text(json.dumps(value))
        def execute(argv, **kwargs):
            endpoints.append(argv[argv.index('-endpoint')+1])
            code = codes.pop(0)
            if isinstance(code, Exception): raise code
            if code == 0 or premature_receipt:
                Path(argv[argv.index('-receipt')+1]).write_text(json.dumps({'native_tdx_armtls_verified': True,
                    'image_and_launch_verified': True, 'result': {'passed': True, 'seconds': .1, 'checks': {}}}))
            return subprocess.CompletedProcess(argv, code, stdout=b'')
        with tempfile.TemporaryDirectory() as directory:
            runner.directory = Path(directory)
            (runner.directory/'operator.pem').write_text('synthetic test operator key')
            with patch('run.subprocess.run', side_effect=execute), patch('run.time.sleep'):
                error = None
                try: runner.phase(0, operation, 1, retry_start=operation == 'init')
                except Exception as e: error = e
        return runner, endpoints, restarts, error

    def test_known_absence_replaces_tunnel_before_one_retry(self):
        r, endpoints, restarts, error = self.attempt([75, 0])
        self.assertIsNone(error)
        self.assertEqual(endpoints, ['https://127.0.0.1:1001', 'https://127.0.0.1:1002'])
        self.assertEqual(restarts, [0])
        self.assertTrue(r.state['phases'][0]['not_dispatched'])
        self.assertTrue(r.state['phases'][1]['passed'])

    def test_second_predispatch_failure_stops(self):
        r, endpoints, restarts, error = self.attempt([75, 75])
        self.assertIsInstance(error, ValueError)
        self.assertEqual(len(endpoints), 2); self.assertEqual(restarts, [0])
        self.assertFalse(any(p['passed'] for p in r.state['phases']))

    def test_idempotent_initialization_keeps_its_startup_window(self):
        r, endpoints, restarts, error = self.attempt([75, 75, 0], operation='init')
        self.assertIsNone(error)
        self.assertEqual(len(endpoints), 3); self.assertEqual(restarts, [0, 0])
        self.assertTrue(r.state['phases'][-1]['passed'])

    def test_unknown_failure_or_receipt_never_allows_retry(self):
        for code, receipt in [(1, False), (75, True), (subprocess.TimeoutExpired('client', 1), False)]:
            _, endpoints, restarts, error = self.attempt([code], premature_receipt=receipt)
            self.assertIsNotNone(error)
            self.assertEqual(len(endpoints), 1); self.assertEqual(restarts, [])


if __name__ == '__main__': unittest.main()
