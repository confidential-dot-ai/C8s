import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
import run


class FailureInspection(unittest.TestCase):
    def inspect(self, unavailable=None):
        with tempfile.TemporaryDirectory() as directory:
            runner = object.__new__(run.Run)
            runner.directory = Path(directory)
            runner.args = SimpleNamespace(client='verified-client')
            runner.guests = {i: object() for i in range(3)}
            runner.tunnels = {}; runner.etcd = (None, None, ['member0', 'member1', 'member2'])
            failed = {'operation': 'seed', 'passed': False}
            runner.state = {'phases': [failed.copy()]}
            runner.atomic = lambda path, value: path.write_text(json.dumps(value))
            events = []; commands = []; reads = []; opened = []
            runner.event = lambda name, **fields: events.append((name, fields))
            def tunnel(slot):
                opened.append(slot)
                if slot == unavailable: raise ValueError('owned guest unreachable or replaced')
                runner.tunnels[slot] = (None, 'https://127.0.0.1:'+str(1000+slot))
            runner.open_tunnel = tunnel
            def command(label, argv, timeout):
                request = json.loads(Path(argv[argv.index('-request')+1]).read_text())
                commands.append((label, request, timeout))
                return b''
            runner.command = command
            def read(url, path, body, **kwargs):
                reads.append((url, path, body, kwargs))
                if url == 'member1': raise OSError('unreachable member')
                return 200, {'leader': 'same-leader'}
            runner.request = read
            runner.inspect_backends()
            self.assertEqual(runner.state['phases'], [failed])
            samples = json.loads((runner.directory/'failure-member-status.json').read_text())
            return opened, commands, reads, samples, events

    def test_only_status_reads_run_without_replaying_or_reclassifying_failure(self):
        opened, commands, reads, samples, _ = self.inspect()
        self.assertEqual(opened, [0, 1, 2])
        self.assertEqual([q for _, q, _ in commands], [{'operation': 'status', 'target': i} for i in range(3)])
        self.assertTrue(all(timeout == 25 for _, _, timeout in commands))
        self.assertTrue(all(path == '/v3/maintenance/status' and body == {} and
                            opts == {'etcd': True, 'timeout': 5} for _, path, body, opts in reads))
        self.assertEqual([s['http_status'] for s in samples], [200, 0, 200])

    def test_unreachable_or_replaced_guest_is_skipped_without_stopping_cleanup_path(self):
        opened, commands, reads, _, events = self.inspect(unavailable=1)
        self.assertEqual(opened, [0, 1, 2])
        self.assertEqual([q['target'] for _, q, _ in commands], [0, 2])
        self.assertEqual(len(reads), 3)
        self.assertIn(('guest-status-diagnostic-unavailable', {'slot': 1}), events)


if __name__ == '__main__': unittest.main()
