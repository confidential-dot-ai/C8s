import copy
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'cds-ha-metadata'))
import guests
from fixtures import OWNER, COMPONENT, SLOT, selector

RUN = 'cds-ha-123456789abc'

class Safety(unittest.TestCase):
    def test_admin_pass_keeps_owned_destination_and_namespace_policy(self):
        a = guests.admin(RUN, 'expiry')
        self.assertEqual(a['spec']['priority'], 89)
        rule = a['spec']['egress'][0]
        self.assertEqual(rule['action'], 'Pass')
        self.assertEqual(rule['to'][0]['pods'], a['spec']['subject']['pods'])
        self.assertEqual(rule['to'][0]['pods']['podSelector'], selector(RUN))
        self.assertNotIn(6443, [p['portNumber']['port'] for p in rule['ports']])

    def test_partition_retains_only_tunnel_dns_and_public_collateral(self):
        service, p = guests.network(RUN, 1, 'expiry')
        isolated = guests.partition(p)
        self.assertEqual(isolated['spec']['podSelector'], selector(RUN, 'cds', 1))
        self.assertEqual(len(isolated['spec']['ingress']), 1)
        self.assertEqual(isolated['spec']['ingress'][0]['ports'], [{'protocol': 'TCP', 'port': 6443}])
        self.assertEqual(len(isolated['spec']['egress']), 2)
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

if __name__ == '__main__': unittest.main()
