import copy
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'cds-ha-metadata'))
from fixtures import NS, selector
import faults

RUN = 'cds-ha-123456789abc'


class Runner:
    def __init__(self):
        self.run = RUN; self.guests = {}; self.vmis = {}; self.mutations = []; self.events = []
        self.state = {'guest_placements': []}; self.fail_pause = None
        self.kube = SimpleNamespace(call=self.call)
        for slot in range(3):
            name = RUN+'-g'+str(slot)+'-a'; uid = 'vm-'+str(slot)
            self.guests[slot] = {'uid': uid, 'item': {'metadata': {'name': name}}}
            self.vmis[name] = {'metadata': {'name': name, 'namespace': NS, 'uid': 'vmi-'+str(slot),
                'labels': selector(RUN, 'cds', slot)['matchLabels'],
                'ownerReferences': [{'kind': 'VirtualMachine', 'uid': uid, 'controller': True}]},
                'status': {'nodeName': 'node-'+str(slot), 'phase': 'Running', 'conditions': []}}
            self.state['guest_placements'].append({'vm_uid': uid, 'vmi_uid': 'vmi-'+str(slot),
                                                  'node': 'node-'+str(slot), 'slot': slot})

    def live(self): pass
    def current(self, row): return row['item']
    def event(self, name, **fields): self.events.append((name, fields))

    def call(self, method, path, body=None, expected=(200,)):
        if method == 'GET': return 200, copy.deepcopy(self.vmis[path.rsplit('/', 1)[1]])
        assert method == 'PUT' and path.startswith(faults.CONTROL)
        name, action = path[len(faults.CONTROL):].split('/')
        self.mutations.append((name, action))
        self.vmis[name]['status']['conditions'] = [{'type': 'Paused', 'status': 'True' if action == 'pause' else 'False'}]
        if name == self.fail_pause and action == 'pause': raise ValueError('ambiguous pause response')
        return 200, None


class QuorumFault(unittest.TestCase):
    def test_pause_is_observed_and_exception_restores_both_guests(self):
        r = Runner()
        with self.assertRaisesRegex(RuntimeError, 'phase failed'):
            with faults.paused_guests(r, [1, 2]):
                self.assertTrue(all(faults.is_paused(faults.current_guest(r, s)) for s in [1, 2]))
                self.assertFalse(faults.is_paused(faults.current_guest(r, 0)))
                raise RuntimeError('phase failed')
        self.assertEqual([a for _, a in r.mutations], ['pause', 'pause', 'unpause', 'unpause'])
        self.assertTrue(all(not faults.is_paused(v) for v in r.vmis.values()))

    def test_ambiguous_second_pause_restores_every_requested_guest(self):
        r = Runner(); r.fail_pause = RUN+'-g2-a'
        with self.assertRaisesRegex(ValueError, 'ambiguous pause'):
            with faults.paused_guests(r, [1, 2]): self.fail('fault must not be accepted')
        self.assertEqual([a for _, a in r.mutations], ['pause', 'pause', 'unpause', 'unpause'])
        self.assertFalse(any(n == 'guest-quorum-loss-observed' for n, _ in r.events))
        self.assertTrue(all(not faults.is_paused(v) for v in r.vmis.values()))

    def test_replaced_or_foreign_guest_is_never_mutated(self):
        for change in [lambda v: v['metadata'].update(uid='replacement'),
                       lambda v: v['metadata'].update(ownerReferences=[]),
                       lambda v: v['metadata'].update(labels={}),
                       lambda v: v['status'].update(nodeName='other-worker')]:
            r = Runner(); change(r.vmis[RUN+'-g1-a'])
            with self.assertRaisesRegex(ValueError, 'incarnation'):
                with faults.paused_guests(r, [1, 2]): self.fail('foreign guest accepted')
            self.assertEqual(r.mutations, [])

    def test_preexisting_pause_and_different_targets_are_refused(self):
        r = Runner(); r.vmis[RUN+'-g1-a']['status']['conditions'] = [{'type': 'Paused', 'status': 'True'}]
        with self.assertRaisesRegex(ValueError, 'already paused'):
            with faults.paused_guests(r, [1, 2]): self.fail('preexisting pause accepted')
        for slots in [[0, 1], [1], [1, 1], [2, 1]]:
            with self.assertRaises(ValueError):
                with faults.paused_guests(r, slots): self.fail('wrong target accepted')
        self.assertEqual(r.mutations, [])

    def test_all_three_voters_and_one_observed_leader_are_required(self):
        states = [{'answered': True, 'status': {'id': str(i), 'leader': '1',
            'state': 'Leader' if i == 1 else 'Follower', 'serving': {'ok': True},
            'voters': ['0', '1', '2']}} for i in range(3)]
        self.assertEqual(faults.raft_leader(states), 1)
        for change in [lambda s: s[0].update(answered=False),
                       lambda s: s[1]['status'].update(state='Follower'),
                       lambda s: s[0]['status'].update(state='Leader'),
                       lambda s: s[0]['status'].update(voters=['0']),
                       lambda s: s[0]['status'].update(non_voters=['2']),
                       lambda s: s[0]['status'].update(id='1'),
                       lambda s: s[0]['status'].update(leader='0')]:
            bad = copy.deepcopy(states); change(bad)
            with self.assertRaises(ValueError): faults.raft_leader(bad)


if __name__ == '__main__': unittest.main()
