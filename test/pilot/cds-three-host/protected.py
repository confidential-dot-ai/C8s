#!/usr/bin/env python3
"""Combined three-host HA and hardware custody qualification; opt-in, no CI.

Uses one fixed TDX image, three CDS guests, three etcd members/adapters, and
two SNP custody chips. Initial and replacement disks are populated before the
live replay checkpoint. This is a total-loss proof, not an image-upgrade test.
"""
import argparse
import base64
import copy
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import sys
import tarfile
import time
import urllib.parse

import run as ha
from fixtures import NS, OWNER, need
import guests


def custody_module():
    # Both existing command-line runners are called run.py. Limit that alias
    # to import time; never replace the running HA controller's module.
    directory = Path(__file__).resolve().parents[1]/'cds-sealed-recovery/hardware'
    native = ha.metadata.load_module('cds_protected_native', directory/'run.py')
    previous = sys.modules.get('run')
    sys.modules['run'] = native
    sys.path.insert(0, str(directory))
    try:
        return (ha.metadata.load_module('cds_protected_custody', directory/'integrated.py'), native,
                ha.metadata.load_module('cds_protected_tdx_artifacts', directory/'tdx_artifacts.py'))
    finally:
        sys.path.remove(str(directory))
        if previous is None: sys.modules.pop('run', None)
        else: sys.modules['run'] = previous


integrated, native, tdx_artifacts = custody_module()


def protected_config(config, endpoint, root_ca, prefix):
    config = copy.deepcopy(config)
    nodes = json.loads(config['nodes'])
    need(len(nodes['measurements']) == 2 and
         {k: v for k, v in nodes['measurements'][0].items() if k != 'name'} ==
         {k: v for k, v in nodes['measurements'][1].items() if k != 'name'},
         'one fixed independently pinned TDX image required')
    nodes['measurements'] = nodes['measurements'][:1]
    config['nodes'] = json.dumps(nodes)
    config['ha']['objectWALPilot'] = {
        'bucket': 'inline-only', 'region': 'fixture', 'prefix': prefix,
        'endpoint': endpoint, 'pathStyle': True, 'metadataEndpoint': endpoint,
        'metadataRootCA': root_ca, 'directState': True, 'atomicOperatorWrites': True,
        # Public placeholder only; enrollment replaces exactly this field.
        'recoveryAuthority': base64.b64encode(bytes(32)).decode()}
    return config


def enrolled_launch(template, enrolled):
    import yaml
    raw = base64.b64decode(enrolled['result']['launch'], validate=True)
    final = yaml.safe_load(raw)
    original = copy.deepcopy(template)
    public = final['ha']['objectWALPilot'].pop('recoveryAuthority')
    placeholder = original['ha']['objectWALPilot'].pop('recoveryAuthority')
    need(final == original and public != placeholder and
         enrolled['result']['derivation']['authority_public'] == public,
         'enrollment must change exactly the public authority')
    return raw


class Custody(integrated.Integrated):
    def prepare(self, template, launch):
        import yaml
        need(not self.state['resources'], 'new custody journal required')
        measurement, hashes = native.image_inputs(self.args.image)
        config = yaml.safe_load(template.read_text())
        self.state.update(measurement=measurement, artifact_hashes=hashes,
                          prefix=config['ha']['objectWALPilot']['prefix'],
                          expected_product_line='Genoa')
        self.save()
        baseline = self.health(capture=True)
        _, storage = self.kube.call('GET', '/apis/storage.k8s.io/v1/storageclasses/local-path')
        need(storage.get('reclaimPolicy') == 'Delete' and
             storage.get('volumeBindingMode') == 'WaitForFirstConsumer', 'owned custody disk cleanup contract unavailable')
        for archive, files in [('root.tar.gz', [('disk.raw', 'disk.img')]),
                               ('boot.tar.gz', [('guest-smp2.igvm', 'guest-smp2.igvm'), ('manifest.json', 'manifest.json')])]:
            with tarfile.open(self.directory/archive, 'w:gz', compresslevel=1) as output:
                for src, dst in files: output.add(Path(self.args.image)/src, arcname=dst, recursive=False)
        def stage(node, config):
            name = 'cds-snp-'+secrets.token_hex(6)
            items = self.render(name, node, baseline[node]['uid'], config)
            self.populate(items, hashes, name)
            return next(x for x in items if x['kind'] == 'VirtualMachine')
        self.source = stage(self.args.nodes[0], template)
        row, _ = self.boot(self.source, 'enroll')
        self.enrolled = self.phase(self.source, 'enroll', template, {'guest_svn': 0, 'tcb_version': 0}, {})
        self.stop_forward(); self.remove(row); self.wait_absent(native.VMI+'/'+self.source['metadata']['name'])
        launch.write_bytes(enrolled_launch(config, self.enrolled)); launch.chmod(0o600)
        # The copy verifier uses the exact final CDS launch; no private key is here.
        (self.directory/'cds-launch.yaml').write_bytes(launch.read_bytes())
        self.custodian_launch = template
        self.custodian_identity = self.enrolled['result']['derivation']
        self.custody_copy = None
        self.parameters = self.enrolled['result']['parameters']
        self.collateral = json.loads((self.directory/'enroll-collateral.json').read_text())
        self.destination = stage(self.args.nodes[1], launch)
        pair = self.boot_pair([('source', self.source), ('destination', self.destination)], 'copy')
        self.custodian_port = self.tunnel(self.source, 'copy-source')
        self.copied = self.phase(self.destination, 'copy', launch, self.parameters, self.collateral)
        source = json.loads((self.directory/'copy-custodian-receipt.json').read_text())
        need(self.copied['chip_id_sha256'] != self.enrolled['chip_id_sha256'] and
             source['chip_id_sha256'] == self.enrolled['chip_id_sha256'] and
             self.copied['result']['derivation']['authority_public'] == self.custodian_identity['authority_public'],
             'second independently attested custody chip required')
        self.atomic(self.directory/'custody-copy.json', self.copied['result']['copy'])
        self.state['custody_copy_sha256'] = native.digest(self.directory/'custody-copy.json')
        self.stop_forward()
        for row, _ in pair.values():
            self.remove(row); self.wait_absent(native.VMI+'/'+row['item']['metadata']['name'])
        self.state['custody_prepared'] = True; self.save()

    def start(self, generation, launch):
        need(generation in ('initial', 'replacement'), 'fixed custody generation required')
        if generation == 'replacement':
            need(native.digest(self.directory/'custody-copy.json') == self.state['custody_copy_sha256'], 'sealed copy changed')
            self.custody_copy = json.loads((self.directory/'custody-copy.json').read_text())
            self.custodian_identity = self.copied['result']['derivation']
            self.custodian_launch = launch
            self.state['excluded_recovery_nodes'] = [self.args.nodes[0]]
            vm = self.destination
        else: vm = self.source
        node = vm['spec']['template']['spec']['nodeSelector']['kubernetes.io/hostname']
        need(node not in self.state.get('excluded_recovery_nodes', []), 'source custody host excluded')
        self.active, self.active_uid = self.boot(vm, generation+'-custody')
        self.custodian_port = self.tunnel(vm, generation+'-custody')

    def stop(self):
        self.stop_forward()
        self.remove(self.active)
        self.wait_absent(native.VMI+'/'+self.active['item']['metadata']['name'])
        owner = self.active['item']['metadata']['labels'][native.LABEL]
        _, pods = self.kube.call('GET', '/api/v1/namespaces/'+native.NS+'/pods?labelSelector='+urllib.parse.quote(native.LABEL+'='+owner))
        need(not pods['items'], 'source custody launcher still present')
        return self.active_uid

    def delegate_three(self, generation, recipients, launch):
        need(len(recipients) == 3 and len({r['public_key'] for r in recipients}) == 3 and
             len({r['nonce'] for r in recipients}) == 3, 'three distinct custody recipients required')
        batch = []
        for slot, recipient in enumerate(recipients):
            label = f'{generation}-recipient-{slot}'
            self.atomic(self.directory/(label+'-request.json'), recipient)
            self.command(label+'-verify', [self.args.probe, '-platform', 'tdx', '-custody-request',
                '-manifest', str(Path(self.args.tdx_image)/'manifest.json'),
                '-request', str(self.directory/(label+'-request.json')), '-launch', str(launch),
                '-receipt', str(self.directory/(label+'-receipt.json')),
                '-collateral', str(self.directory/(label+'-collateral.json'))], timeout=60)
            proof = json.loads((self.directory/(label+'-receipt.json')).read_text())
            need(proof.get('platform') == 'tdx' and all(proof.get(k) is True for k in (
                'attestation_chain_verified', 'collateral_verified', 'revocations_checked',
                'image_pins_verified', 'launch_binding_verified')), 'complete native TDX recipient evidence required')
            batch.append({'recipient': recipient, 'collateral': json.loads((self.directory/(label+'-collateral.json')).read_text())})
        label = generation+'-delegate-three'
        request = {'operation': 'delegate-three', 'nonce': base64.b64encode(secrets.token_bytes(32)).decode(),
                   'measurement': self.state['measurement'], 'parameters': self.parameters, 'custodies': batch}
        if self.custody_copy is not None: request['copy'] = self.custody_copy
        self.atomic(self.directory/(label+'-request.json'), request)
        code, _ = self.http(self.custodian_port, 'POST', '/v1/start', request)
        need(code == 202, 'custody batch dispatch refused or ambiguous; never retry')
        end = time.monotonic()+60
        while time.monotonic() < end:
            code, reply = self.http(self.custodian_port, 'GET', '/v1/result')
            if code == 200: break
            need(code == 202, 'custody batch result unavailable'); time.sleep(.1)
        else: raise TimeoutError('bounded custody batch deadline')
        self.atomic(self.directory/(label+'-reply.json'), reply)
        receipt = self.verify_phase(self.active['item'], label, self.custodian_launch)
        expected_chip = (self.copied if generation == 'replacement' else self.enrolled)['chip_id_sha256']
        need(receipt['chip_id_sha256'] == expected_chip and
             receipt['result']['derivation'] == self.custodian_identity and
             len(receipt['result']['custody_grants']) == 3, 'custody chip, identity or batch changed')
        self.state.setdefault('batch_receipts', {})[generation] = receipt
        self.save()
        return receipt['result']['custody_grants']


class Run(ha.Run):
    def __init__(self, args):
        super().__init__(args)
        custody_args = copy.copy(args)
        custody_args.directory = str(self.directory/'custody')
        Path(custody_args.directory).mkdir(mode=0o700, exist_ok=True)
        custody_args.nodes, custody_args.platform = args.snp_nodes, 'snp'
        custody_args.fixture_expires = self.state['expires']
        custody_args.image, custody_args.renderer = args.snp_image, args.custody_renderer
        self.custody = Custody(custody_args, self.kube, self.atomic)

    def artifacts(self):
        pins, hashes = tdx_artifacts.image_inputs(self.args.tdx_image)
        image = {'directory': self.args.tdx_image, 'pins': pins, 'disk_sha256': hashes['disk.raw']}
        self.state['images'] = {v: copy.deepcopy(image) for v in ('a', 'b')}
        archive = str(ha.archive_image(self.args.tdx_image))
        self.state['archives'] = {v: archive for v in ('a', 'b')}
        self.state['tool_hashes'] = {k: native.digest(getattr(self.args, k)) for k in (
            'client', 'probe', 'renderer', 'custody_renderer', 'etcd_binary', 'metadata_binary', 'collateral_proxy_binary')}
        self.state['combined_hardware_ha_passed'] = False
        self.save()

    def launch(self):
        import yaml
        origin = f'https://{self.run}-api.{NS}.svc.cluster.local:9443'
        config = protected_config(self.launch_config(), origin, (self.directory/'api-ca.pem').read_text(), self.run)
        template = self.directory/'enrollment-launch.yaml'
        template.write_text(yaml.safe_dump(config, sort_keys=True)); template.chmod(0o600)
        self.atomic(self.directory/'provision.json', {'metadata_token': self.token,
            'credentials': {'access_key_id': 'synthetic', 'secret_access_key': 'test-only'}})
        launch = self.directory/'launch.yaml'
        self.custody.prepare(template, launch)
        self.state['launch_sha256'] = native.digest(launch); self.save()
        return launch

    def boot_generation(self, pending, variant):
        if variant == 'b': need(self.state.get('all_cds_lost'), 'all-loss barrier required before replacement')
        # The existing bounded native boot helper starts all three owned VMs
        # before readiness checks; it never starts an unjournaled instance.
        ready = integrated.Integrated.boot_pair(self, [(str(i), pending[i, variant]) for i in range(3)], variant)
        for slot in range(3):
            row, uid = ready[str(slot)]
            self.guests[slot] = row
            self.state.setdefault('guest_placements', []).append({'slot': slot, 'variant': variant,
                'vm_uid': row['uid'], 'vmi_uid': uid, 'node': self.state['nodes'][slot]['name'],
                'node_uid': self.state['nodes'][slot]['uid']})
            self.save(); self.start_console(row); self.open_tunnel(slot)
        for slot in range(3):
            self.phase(slot, 'init', slot, retry_start=True)
            self.phase(slot, 'startup', slot)

    def provision_generation(self, generation, launch):
        recipients = [self.phase(i, 'custody-request', i)['recipient'] for i in range(3)]
        fingerprints = [hashlib.sha256(base64.b64decode(r['public_key'], validate=True)).hexdigest() for r in recipients]
        previous = self.state.setdefault('recipient_keys', {})
        need(not set(fingerprints).intersection(previous.get('initial', [])), 'replacement reused a recipient key')
        grants = self.custody.delegate_three(generation, recipients, launch)
        previous[generation] = fingerprints; self.save()
        for slot in range(3):
            self.phase(slot, 'custody-accept', slot, custody=grants[slot])
            operation = 'recovery-enroll' if generation == 'initial' and slot == 0 else 'recovery-restore'
            proof = self.phase(slot, operation, slot)
            digest = proof['registration_sha256']
            need(not self.state.get('registration_sha256') or self.state['registration_sha256'] == digest,
                 'recovery must use the original committed registration and capsule')
            self.state['registration_sha256'] = digest; self.save()
            self.phase(slot, 'provision', slot)
            if generation == 'initial' and slot == 0: self.phase(0, 'recovery-genesis')

    def destroy_initial(self):
        need(set(self.guests) == {0, 1, 2}, 'three initial CDS guests required')
        originals = [x for x in self.state['guest_placements'] if x['variant'] == 'a']
        need(len(originals) == 3 and len({x['vmi_uid'] for x in originals}) == 3, 'three original incarnations required')
        for slot in range(3):
            self.tunnels[slot][0].terminate()
            self.remove(self.guests[slot]) # includes exact VM and VMI absence waits
        custody_uid = self.custody.stop()
        # Independent read-only barrier after all ordinary removals. A timeout,
        # foreign replacement or surviving VMI prevents replacement boot.
        for row in self.guests.values():
            for path in (row['path'], ha.VMI+row['item']['metadata']['name']):
                need(self.kube.call('GET', path, expected=(200, 404))[0] == 404, 'original CDS incarnation still present')
        names = {row['item']['metadata']['name'] for row in self.guests.values()}
        uids = {p['vmi_uid'] for p in originals}
        _, pods = self.kube.call('GET', '/api/v1/namespaces/'+NS+'/pods?labelSelector='+urllib.parse.quote(OWNER+'='+self.run))
        need(not any(p['metadata'].get('labels', {}).get('kubevirt.io/domain') in names or
                     any(o['uid'] in uids for o in p['metadata'].get('ownerReferences', [])) for p in pods['items']),
             'original CDS launcher still present')
        self.guests.clear(); self.tunnels.clear()
        self.state['all_cds_lost'] = {'at': dt.datetime.now(dt.timezone.utc).isoformat(),
            'vmi_uids': [x['vmi_uid'] for x in originals], 'custodian_vmi_uid': custody_uid}
        self.save(); self.event('all-cds-and-source-custodian-lost', **self.state['all_cds_lost'])

    def exercise(self):
        need(not self.state['resources'] and not self.custody.state['resources'], 'fresh combined journals required')
        self.artifacts(); self.etcd = self.setup(); self.setup_proxy()
        launch = self.launch(); pending = {}
        for slot in range(3):
            for item in guests.network(self.run, slot, self.state['expires']): self.create(item)
            for variant in ('a', 'b'):
                items, vm = self.render_guest(slot, variant, launch)
                self.populate(items, variant); pending[slot, variant] = vm
        self.custody.start('initial', launch)
        self.boot_generation(pending, 'a'); self.provision_generation('initial', launch)
        self.phase(0, 'seed')
        for slot in (1, 2): self.phase(slot, 'attach', slot)
        self.phase(0, 'burst')
        self.phase(0, 'prepare', 2); self.phase(2, 'prepare', 2)
        self.isolate_guest(2, True)
        try:
            time.sleep(7)
            self.phase(2, 'refuse', 2); self.phase(0, 'survive', 2)
        finally: self.isolate_guest(2, False)
        self.phase(0, 'heal'); self.phase(0, 'roll-safe')
        self.refresh_metadata_observers(); self.phase(0, 'prepare', 0)
        try:
            for row in self.etcd.policies[:2]: self.set_policy(row, True)
            self.wait_no_leader(self.etcd.etcd_urls)
            self.phase(0, 'refuse', 0); self.phase(1, 'recovery-refuse', 1)
        finally:
            for row in self.etcd.policies[:2]: self.set_policy(row, False)
        self.wait_members(self.etcd.etcd_urls)
        self.phase(0, 'heal'); self.health(); self.custody.health()
        before = self.phase(0, 'recovery-checkpoint')
        need(before.get('encrypted_witness_committed') and before.get('revocation_acknowledged_before_loss'), 'durable checkpoint required')
        self.destroy_initial()
        self.custody.start('replacement', launch)
        self.boot_generation(pending, 'b'); self.provision_generation('replacement', launch)
        after = self.phase(0, 'recovery-check')
        need(after['ca_fingerprint'] == before['ca_fingerprint'] and all(after.get(k) is True for k in (
            'same_ca_all_replicas', 'live_spent_tokens_rejected', 'revocation_preserved',
            'original_leaf_and_secret_positive_control')), 'combined acceptance evidence incomplete')
        placements = self.state['guest_placements']
        need(len(placements) == len({x['vmi_uid'] for x in placements}) == 6 and
             len({x['node_uid'] for x in placements}) == 3, 'six native incarnations on three workers required')
        self.health(); self.custody.health()
        self.state['combined_hardware_ha_passed'] = True
        self.state['production_ready'] = False
        self.event('combined-hardware-ha-passed', ca_fingerprint=after['ca_fingerprint'], production_ready=False)

    def cleanup(self):
        failures = []
        for cleanup in (super().cleanup, self.custody.cleanup):
            try: cleanup()
            except Exception as error: failures.append(str(error))
        need(not failures, 'owned combined cleanup incomplete: '+'; '.join(failures))

    def audit(self):
        paths, owners = set(), {(OWNER, self.run)}
        for runner in (self, self.custody):
            label = OWNER if runner is self else native.LABEL
            for row in runner.state['resources']:
                path = self.resource_path(row['item']) if runner is self else native.resource_path(row['item'])
                need(path == row['path'], 'audit journal path differs'); paths.add(path)
                owners.add((label, row['item']['metadata']['labels'][label]))
                if row.get('pv'): paths.add('/api/v1/persistentvolumes/'+row['pv']['name'])
                if row['item']['kind'] == 'VirtualMachine': paths.add(ha.VMI+row['item']['metadata']['name'])
        remaining = [p for p in sorted(paths) if self.kube.call('GET', p, expected=(200, 404))[0] != 404]
        for label, owner in sorted(owners):
            _, pods = self.kube.call('GET', '/api/v1/pods?labelSelector='+urllib.parse.quote(label+'='+owner))
            remaining.extend('owned-pod/'+p['metadata']['name'] for p in pods['items'])
        self.atomic(self.directory/'cleanup-audit.json', {'read_only_independent_audit': True,
            'resource_paths_checked': len(paths), 'cleanup_verified': not remaining, 'remaining': remaining})
        need(not remaining, 'owned combined resources remain')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['run', 'cleanup', 'audit'])
    for field in ('directory', 'kubeconfig', 'kubectl', 'virtctl', 'cloud-helpers', 'tools-image',
                  'etcd-binary', 'metadata-binary', 'source-tree', 'renderer', 'client', 'tdx-image',
                  'snp-image', 'custody-renderer', 'probe', 'collateral-proxy-binary'):
        parser.add_argument('--'+field, required=True)
    parser.add_argument('--nodes', nargs=3, required=True)
    parser.add_argument('--snp-nodes', nargs=2, required=True)
    args = parser.parse_args(); args.backend, args.platform = 'direct-state', 'tdx'
    need(len(set(args.nodes+args.snp_nodes)) == 5, 'three TDX workers and two distinct SNP custody workers required')
    os.umask(0o077)
    if args.action != 'run':
        need((Path(args.directory)/'journal.json').is_file() and
             (Path(args.directory)/'custody/journal.json').is_file(), 'both existing ownership journals required')
    runner = Run(args)
    if args.action == 'audit': runner.audit(); return
    if args.action == 'cleanup': runner.cleanup(); runner.audit(); return
    def interrupted(*_): raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError('combined qualification deadline')))
    signal.alarm(4200)
    try: runner.exercise()
    except BaseException as error:
        runner.event('combined-qualification-failed', failure=type(error).__name__, detail=str(error))
        runner.diagnostics(); raise
    finally:
        signal.alarm(0)
        runner.cleanup(); runner.audit()
        if 'nodes_before' in runner.state: runner.health()
        if 'nodes_before' in runner.custody.state: runner.custody.health()


if __name__ == '__main__': main()
