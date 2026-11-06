import io
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
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

    def test_real_setup_result_refresh_preserves_adapters_and_replaces_only_observers(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = self.runner(directory)
            binary = runner.directory/'fixture-binary'; binary.write_bytes(b'fixture')
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            runner.run = 'cds-ha-0123456789ab'
            runner.args = SimpleNamespace(source_tree='a'*40, nodes=['worker-'+str(i) for i in range(3)],
                tools_image='example.invalid/tools@sha256:'+'a'*64, etcd_binary=str(binary), metadata_binary=str(binary))
            runner.state = {'resources': [], 'expires': '2099-01-01T00:00:00Z'}
            runner.live = runner.save = lambda: None
            runner.health = lambda **_: {name: {'uid': '00000000-0000-0000-0000-00000000000'+str(i)}
                                       for i, name in enumerate(runner.args.nodes)}
            runner.kube = Mock()
            runner.kube.call.return_value = (200, {'items': [
                {'metadata': {'name': 'cloud-project-boundaries'}, 'spec': {'priority': 90}}]})
            def create(item):
                row = {'item': item, 'uid': item['metadata']['name']+'-uid'}
                runner.state['resources'].append(row)
                return row
            runner.create = create; runner.ready = lambda row: row; runner.remove = lambda row: None
            runner.kubectl = lambda *args: list(args)
            runner.command = lambda name, *args, **kwargs: (
                f'{digest}  /data/bin/etcd\n{digest}  /data/bin/metadata\n'.encode()
                if name.endswith('-hash') else b'')
            runner.metadata_status_forwards = {}; runner.forwards = []; runner.tls_names = {}
            identities = {}
            def forward(self, row, port):
                origin = 'https://127.0.0.1:'+str(10000+len(identities))
                identities[origin] = 'member'+row['item']['metadata']['labels'][run.SLOT]
                self.forwards.append((Mock(), io.StringIO()))
                self.tls_names[origin] = row['item']['metadata']['name']
                return origin
            runner.wait_members = lambda urls: [{'header': {'cluster_id': '123', 'member_id': identities[url]},
                                                 'leader': 'member0'} for url in urls]
            cert = {'tls.crt': b'cert', 'tls.key': b'key'}
            certificates = {'etcd_ca': b'ca', 'members': [cert]*3, 'adapters': [cert]*3, 'client': cert}
            # Run the actual setup method and the actual Run.forward override.
            # Replace only infrastructure effects, not the setup result shape.
            with patch.object(run.metadata, 'certificates', return_value=certificates), \
                 patch.object(run.metadata.Run, 'forward', forward):
                original = runner.setup(); runner.etcd = original
                old = list(runner.metadata_status_forwards.values())
                adapters = [handle for handle in runner.forwards if handle not in old]
                runner.refresh_metadata_observers()
            self.assertEqual(len(original), 6)
            for field in ('members', 'policies', 'adapters', 'adapter_urls'):
                self.assertIs(getattr(runner.etcd, field), getattr(original, field))
            self.assertTrue(set(runner.etcd.etcd_urls).isdisjoint(original.etcd_urls))
            self.assertEqual(set(runner.metadata_status_forwards), set(runner.etcd.etcd_urls))
            self.assertEqual(len(runner.forwards), 6)
            for process, log in old:
                process.terminate.assert_called_once(); self.assertTrue(log.closed)
            self.assertEqual(len(adapters), 3)
            for process, log in adapters:
                process.terminate.assert_not_called(); self.assertFalse(log.closed)
            runner.event.assert_any_call('metadata-status-observers-refreshed', members=3)


if __name__ == '__main__': unittest.main()
