"""Observable faults scoped to the exact owned guest incarnations."""
from contextlib import contextmanager
import time
from fixtures import NS, need, selector

VMI = '/apis/kubevirt.io/v1/namespaces/'+NS+'/virtualmachineinstances/'
CONTROL = '/apis/subresources.kubevirt.io/v1/namespaces/'+NS+'/virtualmachineinstances/'


def raft_leader(replicas):
    need(len(replicas) == 3 and all(r.get('answered') for r in replicas), 'three answered Raft statuses required')
    states = [r['status'] for r in replicas]
    members = {s.get('id') for s in states}
    leaders = [i for i, s in enumerate(states) if s.get('state') == 'Leader']
    need(len(members) == 3 and None not in members and '' not in members and len(leaders) == 1,
         'three distinct members and exactly one observed leader required')
    leader = leaders[0]
    need(all(s.get('serving', {}).get('ok') and s.get('leader') == states[leader]['id'] and
             len(s.get('voters', [])) == 3 and set(s['voters']) == members and not s.get('non_voters')
             for s in states), 'all replicas must serve under the same three-voter configuration')
    return leader


def current_guest(runner, slot):
    row = runner.guests[slot]
    vm = runner.current(row)
    name = vm['metadata']['name']
    placements = [p for p in runner.state['guest_placements'] if p['vm_uid'] == row['uid']]
    need(len(placements) == 1 and placements[0]['slot'] == slot, 'unique owned guest placement required')
    _, vmi = runner.kube.call('GET', VMI+name)
    m = vmi['metadata']; expected = placements[0]
    need(m['name'] == name and m.get('namespace') == NS and m['uid'] == expected['vmi_uid'] and
         not m.get('deletionTimestamp') and
         all(m.get('labels', {}).get(k) == v for k, v in selector(runner.run, 'cds', slot)['matchLabels'].items()) and
         any(o.get('kind') == 'VirtualMachine' and o.get('uid') == row['uid'] and o.get('controller')
             for o in m.get('ownerReferences', [])) and
         vmi.get('status', {}).get('nodeName') == expected['node'] and
         vmi['status'].get('phase') == 'Running', 'guest incarnation, owner or placement changed')
    return vmi


def is_paused(vmi):
    return any(c.get('type') == 'Paused' and c.get('status') == 'True' for c in vmi['status'].get('conditions', []))


def set_paused(runner, slot, paused):
    vmi = current_guest(runner, slot)
    if is_paused(vmi) != paused:
        action = 'pause' if paused else 'unpause'
        runner.event('guest-pause-requested', slot=slot, paused=paused, vmi_uid=vmi['metadata']['uid'])
        # One mutation only. A failed/ambiguous pause still enters restoration.
        runner.kube.call('PUT', CONTROL+vmi['metadata']['name']+'/'+action, {}, expected=(200, 202, 204))
        end = time.monotonic()+15
        while True:
            vmi = current_guest(runner, slot)
            if is_paused(vmi) == paused: break
            need(time.monotonic() < end, 'guest pause condition was not observed')
            time.sleep(.5)
    runner.event('guest-pause-observed', slot=slot, paused=paused, vmi_uid=vmi['metadata']['uid'])


@contextmanager
def paused_guests(runner, slots):
    need(slots == [1, 2], 'quorum fault may pause only owned guest slots one and two')
    requested = []
    try:
        for slot in slots:
            runner.live()
            need(not is_paused(current_guest(runner, slot)), 'guest was already paused')
            requested.append(slot)
            set_paused(runner, slot, True)
        runner.event('guest-quorum-loss-observed', paused_slots=slots)
        yield
    finally:
        failures = []
        for slot in reversed(requested):
            try: set_paused(runner, slot, False)
            except Exception as error: failures.append(str(error))
        need(not failures, 'owned guest restoration incomplete: '+'; '.join(failures))
