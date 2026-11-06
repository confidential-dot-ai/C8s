import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import run


class Clock:
    def __init__(self): self.now = 0
    def monotonic(self): return self.now
    def sleep(self, seconds): self.now += seconds


class MetadataObservers(unittest.TestCase):
    def runner(self, directory):
        runner = object.__new__(run.Run)
        runner.directory = Path(directory)
        runner.state = {'etcd_cluster_id': 'cluster'}
        runner.metadata_members = {f'url{i}': f'member{i}' for i in range(3)}
        runner.atomic = lambda path, value: path.write_text(json.dumps(value))
        runner.event = Mock()
        return runner

    def observe(self, response, passes):
        with tempfile.TemporaryDirectory() as directory:
            runner = self.runner(directory); clock = Clock(); calls = []
            def request(url, path, body, *, etcd, timeout):
                self.assertEqual((path, body, etcd), ('/v3/maintenance/status', {}, True))
                self.assertGreater(timeout, 0)
                self.assertLessEqual(timeout, 20-clock.now)
                calls.append((url, timeout))
                clock.now += min(1, timeout)
                return response(url, len(calls), clock)
            runner.request = request
            with patch.object(run, 'time', clock):
                if passes:
                    runner.wait_no_leader(list(runner.metadata_members))
                else:
                    with self.assertRaisesRegex(RuntimeError, 'not independently observed'):
                        runner.wait_no_leader(list(runner.metadata_members))
            saved = json.loads((runner.directory/'metadata-quorum-loss-samples.json').read_text())
            self.assertEqual(runner.event.call_count, int(passes))
            return saved, calls, clock.now

    @staticmethod
    def status(url):
        # Protobuf JSON omits the zero-valued leader field.
        return {'header': {'member_id': 'member'+url[-1], 'cluster_id': 'cluster'}}

    def test_all_three_verified_members_must_report_no_leader(self):
        saved, calls, _ = self.observe(lambda url, _, clock: (200, self.status(url)), True)
        self.assertEqual(len(calls), 3)
        self.assertEqual([s['leader'] for s in saved[-1]['members']], ['0']*3)

    def test_dead_observer_is_retained_as_unknown_and_cannot_prove_quorum_loss(self):
        saved, _, elapsed = self.observe(
            lambda url, _, clock: (0, None) if url == 'url1' else (200, self.status(url)), False)
        failures = [s for row in saved for s in row['members'] if s['http_status'] == 0]
        self.assertTrue(failures)
        self.assertTrue(all(s['leader'] is None and s['member_id'] is None for s in failures))
        self.assertEqual(elapsed, 20)

    def test_wrong_member_or_cluster_never_counts_as_no_leader(self):
        for key in ('member_id', 'cluster_id'):
            def response(url, _, clock):
                status = self.status(url)
                if url == 'url1': status['header'][key] = 'foreign'
                return 200, status
            with self.subTest(key=key): self.observe(response, False)

    def test_late_complete_sample_does_not_extend_observation_deadline(self):
        def response(url, number, clock):
            if number == 3: clock.now = 21
            return 200, self.status(url)
        self.observe(response, False)

    def test_refresh_closes_only_old_metadata_tunnels_and_requires_healthy_members(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = self.runner(directory)
            old = {url: (Mock(), io.StringIO()) for url in runner.metadata_members}
            adapter = (Mock(), io.StringIO())
            runner.metadata_status_forwards = old.copy()
            runner.forwards = [*old.values(), adapter]
            runner.tls_names = {url: url for url in old}
            rows = [object() for _ in range(3)]; policies = [object()]
            runner.etcd = rows, policies, list(old)
            opened = []
            def forward(row, port):
                self.assertEqual(port, 2379)
                # The production forward validates the exact owned Pod UID.
                opened.append(row)
                self.assertTrue(all(p.terminate.called and log.closed for p, log in old.values()))
                return 'fresh'+str(rows.index(row))
            runner.forward = forward
            runner.wait_members = lambda urls: [self.status(url) for url in urls]
            runner.refresh_metadata_observers()
            self.assertEqual(opened, rows)
            self.assertEqual(runner.etcd, (rows, policies, ['fresh0', 'fresh1', 'fresh2']))
            self.assertEqual(runner.metadata_members, {f'fresh{i}': f'member{i}' for i in range(3)})
            self.assertEqual(runner.forwards, [adapter])
            adapter[0].terminate.assert_not_called()
            self.assertFalse(adapter[1].closed)
            runner.event.assert_called_once_with('metadata-status-observers-refreshed', members=3)


if __name__ == '__main__': unittest.main()
