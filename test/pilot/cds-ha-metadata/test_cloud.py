import copy
import unittest

from fixtures import COMPONENT, NS, OWNER, render, partition, selector
from cloud import Run, resource_path


RUN = 'cds-ha-0123456789ab'
NODES = [{'name': 'worker-'+str(i), 'uid': '00000000-0000-0000-0000-00000000000'+str(i)} for i in range(3)]
IMAGE = 'example.invalid/tools@sha256:'+'a'*64
CERTS = {'etcd_ca': b'ca', 'members': [{'tls.crt': b'cert', 'tls.key': b'key'} for _ in range(3)],
         'adapters': [{'tls.crt': b'cert', 'tls.key': b'key'} for _ in range(3)],
         'client': {'tls.crt': b'cert', 'tls.key': b'key'}}


class FixtureTests(unittest.TestCase):
    def items(self): return render(RUN, NODES, IMAGE, CERTS, '2099-01-01T00:00:00Z')

    def test_three_distinct_uid_pinned_workers_and_bounded_unprivileged_pods(self):
        items = self.items()+render(RUN, NODES, IMAGE, CERTS, '2099-01-01T00:00:00Z', '123', 'x'*32)
        for item in items:
            resource_path(item, RUN)
            if item['kind'] != 'Pod': continue
            spec = item['spec']; slot = int(item['metadata']['labels']['cloud.confidential.ai/cds-ha-slot'])
            self.assertEqual(spec['nodeSelector']['kubernetes.io/hostname'], NODES[slot]['name'])
            self.assertEqual(spec['nodeSelector']['cloud.confidential.ai.node-restriction.kubernetes.io/node-uid'], NODES[slot]['uid'])
            self.assertFalse(spec['automountServiceAccountToken'])
            self.assertLessEqual(spec['activeDeadlineSeconds'], 3600)
            self.assertTrue(spec['securityContext']['runAsNonRoot'])
            self.assertNotIn('hostNetwork', spec)
            for c in spec['containers']+spec.get('initContainers', []):
                self.assertFalse(c['securityContext']['allowPrivilegeEscalation'])
                self.assertEqual(c['securityContext']['capabilities'], {'drop': ['ALL']})
            self.assertFalse(any('hostPath' in v for v in spec['volumes']))
        for bad in [NODES[:2], [NODES[0]]*3]:
            with self.assertRaises(ValueError): render(RUN, bad, IMAGE, CERTS, '')

    def test_admin_pass_is_only_between_owned_pods_and_namespace_policy_still_applies(self):
        admin = next(x for x in self.items() if x['kind'] == 'AdminNetworkPolicy')
        pods = {'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': NS}}, 'podSelector': selector(RUN)}
        self.assertEqual(admin['spec']['subject'], {'pods': pods})
        self.assertEqual(admin['spec']['priority'], 89)
        self.assertEqual(len(admin['spec']['egress']), 1)
        rule = admin['spec']['egress'][0]
        self.assertEqual(rule['action'], 'Pass')
        self.assertEqual(rule['to'], [{'pods': pods}])
        self.assertEqual({p['portNumber']['port'] for p in rule['ports']}, {2379, 2380, 9443})

    def test_partition_does_not_expand_selector_or_touch_another_policy(self):
        policy = next(x for x in self.items() if x['kind'] == 'NetworkPolicy')
        before = copy.deepcopy(policy); isolated = partition(policy)
        self.assertEqual(policy, before)
        self.assertEqual(isolated['spec']['podSelector'], selector(RUN, 'etcd', 0))
        self.assertEqual(isolated['spec']['ingress'], [])
        self.assertEqual(len(isolated['spec']['egress']), 1)
        bad = copy.deepcopy(policy); bad['spec']['podSelector'] = {}
        with self.assertRaises(ValueError): partition(bad)

    def test_foreign_paths_and_names_refused(self):
        item = next(x for x in self.items() if x['kind'] == 'Pod')
        for mutation in [lambda x: x['metadata'].update(namespace='kube-system'),
                         lambda x: x['metadata'].update(name=RUN+'-production'),
                         lambda x: x['metadata']['labels'].update({OWNER: 'foreign'})]:
            bad = copy.deepcopy(item); mutation(bad)
            with self.assertRaises(ValueError): resource_path(bad, RUN)

    def test_replaced_uid_never_reaches_delete(self):
        item = next(x for x in self.items() if x['kind'] == 'Pod')
        row = {'item': item, 'path': resource_path(item, RUN), 'uid': 'expected'}
        value = copy.deepcopy(item); value['metadata']['uid'] = 'replacement'
        class Kube:
            def call(self, method, path, *args, **kwargs):
                if method != 'GET': raise AssertionError('mutation after UID mismatch')
                return 200, value
        r = object.__new__(Run); r.run = RUN; r.kube = Kube()
        with self.assertRaises(ValueError): r.remove(row)

    def test_delete_uses_uid_and_normal_foreground_cleanup(self):
        item = next(x for x in self.items() if x['kind'] == 'Pod')
        row = {'item': item, 'path': resource_path(item, RUN), 'uid': 'expected'}
        value = copy.deepcopy(item); value['metadata']['uid'] = 'expected'; calls = []
        class Kube:
            def call(self, method, path, body=None, **kwargs):
                calls.append((method, path, body))
                return (200, value) if method == 'GET' else (202, None)
        r = object.__new__(Run); r.run = RUN; r.kube = Kube(); r.save = lambda: None; r.wait_absent = lambda _: None
        r.remove(row)
        delete = next(body for method, _, body in calls if method == 'DELETE')
        self.assertEqual(delete['preconditions'], {'uid': 'expected'})
        self.assertEqual(delete['propagationPolicy'], 'Foreground')
        self.assertNotIn('gracePeriodSeconds', delete)
        self.assertTrue(row['deleted'])


if __name__ == '__main__': unittest.main()
