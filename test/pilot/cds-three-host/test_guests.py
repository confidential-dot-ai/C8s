import copy
import hashlib
import tempfile
import subprocess
import sys
import unittest
import secrets
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'cds-ha-metadata'))
import guests
import egress
from fixtures import OWNER, COMPONENT, SLOT, selector

RUN = 'cds-ha-123456789abc'

class Safety(unittest.TestCase):
    def test_applied_policy_uses_delivery_wire_field(self):
        import run
        run.policy_applied({'checks': {'delivered': {'intent': 'test', 'applied_version': 2}}})
        for delivered in [{}, {'version': 2}, {'held': True}, {'applied_version': 2, 'refused': 'conflict'},
                          {'applied_version': 0}, {'applied_version': 2, 'held': True}]:
            with self.assertRaises(ValueError): run.policy_applied({'checks': {'delivered': delivered}})

    def test_admin_pass_keeps_owned_destination_and_namespace_policy(self):
        a = guests.admin(RUN, 'expiry')
        self.assertEqual(a['spec']['priority'], 89)
        rule = a['spec']['egress'][0]
        self.assertEqual(rule['action'], 'Pass')
        self.assertEqual(rule['to'][0]['pods'], a['spec']['subject']['pods'])
        self.assertEqual(rule['to'][0]['pods']['podSelector'], selector(RUN))
        self.assertNotIn(6443, [p['portNumber']['port'] for p in rule['ports']])
        collateral = a['spec']['egress'][1]
        self.assertEqual(collateral['action'], 'Pass')
        self.assertEqual(collateral['to'], [{'pods': egress.destination(RUN)}])
        self.assertEqual(collateral['ports'], [{'portNumber': {'protocol': 'TCP', 'port': 3128}}])

    def test_collateral_namespace_and_receiver_are_exclusively_owned(self):
        node = {'name': 'worker', 'uid': 'node-uid'}
        items = egress.render(RUN, node, 'example.invalid/tools@sha256:'+'a'*64, 'expiry')
        for item in items:
            self.assertEqual(guests.resource_path(item, RUN), egress.path(item, RUN))
            bad = copy.deepcopy(item); bad['metadata']['labels'][OWNER] = 'foreign'
            with self.assertRaises(ValueError): guests.resource_path(bad, RUN)
        namespace, policy, service, proxy = items
        self.assertEqual(namespace['metadata']['annotations']['ovn.kubernetes.io/logical_switch'], 'cloud-infra')
        policy['metadata']['annotations']['changed'] = 'only this object'
        self.assertNotIn('changed', service['metadata']['annotations'])
        self.assertEqual(policy['spec']['ingress'][0]['from'][0]['podSelector'], selector(RUN, 'cds'))
        self.assertFalse(proxy['spec']['automountServiceAccountToken'])
        self.assertTrue(proxy['spec']['securityContext']['runAsNonRoot'])
        self.assertFalse(any('hostPath' in v for v in proxy['spec']['volumes']))
        self.assertEqual(proxy['spec']['nodeSelector']['cloud.confidential.ai.node-restriction.kubernetes.io/node-uid'], node['uid'])

    def test_partition_retains_only_tunnel_dns_and_public_collateral(self):
        service, p = guests.network(RUN, 1, 'expiry')
        isolated = guests.partition(p)
        self.assertEqual(isolated['spec']['podSelector'], selector(RUN, 'cds', 1))
        self.assertEqual(len(isolated['spec']['ingress']), 1)
        self.assertEqual(isolated['spec']['ingress'][0]['ports'], [{'protocol': 'TCP', 'port': 6443}])
        self.assertEqual(len(isolated['spec']['egress']), 2)
        self.assertEqual(isolated['spec']['egress'][1], egress.rule(RUN))
        self.assertEqual(service['spec']['clusterIP'], 'None')
        self.assertEqual(service['spec']['selector'], p['spec']['podSelector']['matchLabels'])
        p['spec']['podSelector'] = selector('foreign')
        with self.assertRaises(ValueError): guests.partition(p)

    def test_guest_scope_never_accepts_foreign_namespace_owner_or_name(self):
        service, p = guests.network(RUN, 0, 'expiry')
        for field, value in [('name', 'production-vm'), ('namespace', 'kube-system')]:
            x = copy.deepcopy(service); x['metadata'][field] = value
            with self.assertRaises(ValueError): guests.resource_path(x, RUN)
        x = copy.deepcopy(service); x['metadata']['labels'][OWNER] = 'foreign'
        with self.assertRaises(ValueError): guests.resource_path(x, RUN)
        self.assertTrue(guests.resource_path(service, RUN).endswith('/services/'+RUN+'-g0'))

    def test_cloud_faults_and_cleanup_use_uid_and_no_host_paths(self):
        source = Path(__file__).with_name('run.py').read_text()
        self.assertIn("'path': '/metadata/uid'", source)
        self.assertIn("'path': '/metadata/resourceVersion'", source)
        self.assertNotIn('grace-period=0', source)
        self.assertNotIn('force=true', source)
        renderer = Path(__file__).with_name('render.go').read_text()
        self.assertIn('BridgePodNetwork: true', renderer)
        self.assertIn('RunStrategyManual', renderer)
        self.assertNotIn('HostPath', renderer)

class SparseTransport(unittest.TestCase):
    def test_chunk_is_framed_and_rejects_truncation_and_corruption(self):
        import transfer
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory); data = b'verified image bytes'; token = secrets.token_hex(16)
            digest = hashlib.sha256(data).hexdigest()
            path = p/'chunk'
            process = subprocess.Popen(transfer.chunk_receiver(len(data), digest, str(path), token), stdin=subprocess.PIPE)
            try:
                process.stdin.write(data+b'excess bytes'); process.stdin.flush()
                self.assertEqual(process.wait(timeout=3), 0)  # stdin is still open
            finally:
                process.stdin.close()
                if process.poll() is None: process.kill(); process.wait()
            self.assertEqual(path.read_bytes(), data)
            self.assertEqual((p/'chunk.complete').read_text(), token)
            for index, bad in enumerate([data[:-1], b'x'*len(data)]):
                target = p/('bad'+str(index))
                result = subprocess.run(transfer.chunk_receiver(len(data), digest, str(target), token), input=bad)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(Path(str(target)+'.complete').exists())

    def test_cli_failures_keep_native_upload_retry_contract(self):
        import run
        runner = object.__new__(run.Run)
        with tempfile.TemporaryDirectory() as directory:
            runner.directory = Path(directory)
            with self.assertRaises(RuntimeError):
                runner.command('failed-read-only-probe', [sys.executable, '-c', 'raise SystemExit(1)'])

    def test_receiver_reconstructs_exact_sparse_disk(self):
        import run
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory); disk = p/'disk.raw'
            with disk.open('wb') as f:
                f.write(b'GPT fixture')
                f.seek(32*1024*1024); f.write(b'verified root extent')
            archive = run.archive_image(p)
            out = p/'receiver'; out.mkdir()
            subprocess.run(['tar', '-xzf', str(archive), '-C', str(out)], check=True)
            with disk.open('rb') as original, (out/'disk.img').open('rb') as restored:
                self.assertEqual(hashlib.file_digest(original, 'sha256').digest(),
                                 hashlib.file_digest(restored, 'sha256').digest())
            self.assertEqual((out/'disk.img').stat().st_size, disk.stat().st_size)
            self.assertLess((out/'disk.img').stat().st_blocks*512, 1024*1024)
            self.assertLess(archive.stat().st_size, 64*1024)
            # Extraction checks the ordered archive before publishing its own
            # token; corrupt or missing parts cannot authorize guest startup.
            import transfer
            data = archive.read_bytes(); mid = len(data)//2; parts = [p/'one', p/'two']
            parts[0].write_bytes(data[:mid]); parts[1].write_bytes(data[mid:])
            token = secrets.token_hex(16); marker = p/'extracted'; dest = p/'framed'; dest.mkdir()
            args = transfer.extract_receiver([str(x) for x in parts], hashlib.sha256(data).hexdigest(), str(dest), str(marker), token)
            subprocess.run(args, check=True)
            self.assertEqual(marker.read_text(), token)
            self.assertEqual(hashlib.sha256((dest/'disk.img').read_bytes()).digest(), hashlib.sha256(disk.read_bytes()).digest())
            marker.unlink(); parts[1].write_bytes(b'corrupted')
            self.assertNotEqual(subprocess.run(args).returncode, 0)
            self.assertFalse(marker.exists())

if __name__ == '__main__': unittest.main()
