#!/usr/bin/env python3
"""Sequential Raft/current-state qualification on three owned TDX guests."""
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
import socket
import subprocess
import sys
import tarfile
import time
import urllib.parse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'cds-ha-metadata'))
import cloud as metadata
from fixtures import NS, OWNER, COMPONENT, SLOT, need
import guests

VMI = '/apis/kubevirt.io/v1/namespaces/'+NS+'/virtualmachineinstances/'


class Run(metadata.Run):
    def __init__(self, args):
        super().__init__(args)
        if not self.state['resources']:
            self.state['expires'] = (dt.datetime.now(dt.timezone.utc)+dt.timedelta(minutes=75)).isoformat()
            self.state['backend'] = args.backend
            self.state['three_guest_cds_passed'] = False
            self.state['phases'] = []
            self.save()
        need(self.state['backend'] == args.backend, 'backend differs from journal')
        self.guests = {}; self.tunnels = {}; self.etcd = None
        self.atomic = self.helpers.atomic_json

    def resource_path(self, item): return guests.resource_path(item, self.run)

    def create(self, item):
        if item['kind'] == 'AdminNetworkPolicy':
            need(item['metadata']['name'] == self.run, 'foreign admin fixture')
            item = guests.admin(self.run, self.state['expires'])
        return super().create(item)

    def cleanup(self):
        failures = []
        for row in self.state['resources']:
            if row['item']['kind'] == 'VirtualMachine':
                try: self.remove(row)
                except Exception as error: failures.append(type(error).__name__+': '+str(error))
        try: super().cleanup()
        except Exception as error: failures.append(type(error).__name__+': '+str(error))
        if failures:
            self.state['cleanup_verified'] = False; self.save()
            self.event('guest-cleanup-incomplete', errors=failures)
            raise RuntimeError('owned guest cleanup incomplete; retain journal')

    def remove(self, row):
        super().remove(row)
        if row['item']['kind'] == 'VirtualMachine':
            self.wait_absent(VMI+row['item']['metadata']['name'])

    def isolate_guest(self, slot, isolated):
        row = next(r for r in self.state['resources'] if r['item']['kind'] == 'NetworkPolicy' and r['item']['metadata']['name'] == f'{self.run}-g{slot}')
        self.live(); current = self.current(row)
        need(current['spec']['podSelector'] == row['item']['spec']['podSelector'], 'guest policy scope changed')
        target = guests.partition(row['item']) if isolated else row['item']
        patch = [{'op': 'test', 'path': '/metadata/uid', 'value': row['uid']},
                 {'op': 'test', 'path': '/metadata/resourceVersion', 'value': current['metadata']['resourceVersion']},
                 {'op': 'replace', 'path': '/spec/ingress', 'value': target['spec']['ingress']},
                 {'op': 'replace', 'path': '/spec/egress', 'value': target['spec']['egress']}]
        self.kube.call('PATCH', row['path'], patch, headers={'Content-Type': 'application/json-patch+json'})
        row['isolated'] = isolated; self.save()

    def render_guest(self, slot, variant, launch):
        node = self.state['nodes'][slot]
        items = json.loads(self.command(f'render-{slot}-{variant}', [self.args.renderer, '--platform', 'tdx', '--run', self.run,
            '--slot', str(slot), '--variant', variant, '--node', node['name'], '--node-uid', node['uid'],
            '--launch-file', str(launch), '--expires', self.state['expires'], '--tools-image', self.args.tools_image]))['items']
        vm = guests.validate(items, self.run, slot, variant, node)
        for item in items:
            path = self.resource_path(item); code, _ = self.kube.call('GET', path, expected=(200, 404))
            need(code == 404, 'fresh guest fixture required')
            self.kube.call('POST', path.rsplit('/', 1)[0]+'?dryRun=All', item, expected=(201,))
        return items, vm

    def populate(self, items, variant):
        for item in items:
            if item['kind'] != 'VirtualMachine': self.create(item)
        pop = next(r for r in reversed(self.state['resources']) if r['item']['kind'] == 'Pod' and r['item']['metadata']['name'] == next(x['metadata']['name'] for x in items if x['kind'] == 'Pod'))
        self.ready(pop)
        name = pop['item']['metadata']['name']
        # Reuse the receiver-completion token and independent hash checks of
        # the native hardware runner; no timeout is interpreted as an upload.
        archive = Path(self.state['archives'][variant])
        link = self.directory/('image-'+variant+'.tar.gz')
        if not link.exists(): link.symlink_to(archive)
        self.native.Run.upload(self, name, link.name, '/rootdisk')
        expected = self.state['images'][variant]['disk_sha256']
        answer = self.command(name+'-hash', self.kubectl('exec', name, '--', 'sha256sum', '/rootdisk/disk.img')).decode().strip()
        need(answer == expected+'  /rootdisk/disk.img', 'uploaded guest image differs')
        self.remove(pop)

    def boot_guest(self, vm, slot, variant):
        row, uid = self.native.Run.boot(self, vm, f'guest-{slot}-{variant}')
        self.guests[slot] = row
        _, vmi = self.kube.call('GET', VMI+vm['metadata']['name'])
        need(vmi['metadata']['uid'] == uid, 'guest identity changed')
        self.state.setdefault('guest_placements', []).append({'slot': slot, 'variant': variant, 'vm_uid': row['uid'],
            'vmi_uid': uid, 'node': vmi['status']['nodeName'], 'node_uid': self.state['nodes'][slot]['uid']})
        self.save()
        self.open_tunnel(slot)

    def open_tunnel(self, slot):
        row = self.guests[slot]; self.current(row)
        if slot in self.tunnels:
            process = self.tunnels[slot][0]; process.terminate()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired: process.kill(); process.wait()
        with socket.socket() as sock: sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
        name = row['item']['metadata']['name']
        log = (self.directory/(name+'-tunnel.log')).open('ab')
        process = subprocess.Popen([self.args.virtctl, '--kubeconfig', self.args.kubeconfig, '-n', NS,
            'port-forward', 'vmi/'+name, f'{port}:6443', '--address=127.0.0.1'], stdout=log, stderr=log)
        self.forwards.append((process, log)); self.tunnels[slot] = (process, 'https://127.0.0.1:'+str(port))
        # Do not make a speculative guest connection: virtctl can stop accepting
        # after an early guest dial fails while leaving its process alive.
        time.sleep(.3); need(process.poll() is None, 'VM tunnel exited')

    def phase(self, agent, operation, target=0, retry_start=False):
        self.live(); row = self.guests[agent]; self.current(row)
        need(self.tunnels[agent][0].poll() is None, 'VM tunnel exited')
        q = {'operation': operation, 'target': target}
        if operation == 'init':
            q['operator_key'] = base64.b64encode((self.directory/'operator.pem').read_bytes()).decode()
            if self.args.backend != 'raft': q['provision'] = json.loads((self.directory/'provision.json').read_text())
        deadline = time.monotonic()+(180 if retry_start else 0)
        while True:
            label = f'{len(self.state["phases"]):03}-{operation}-g{agent}'
            self.state['phases'].append({'label': label, 'operation': operation, 'agent': agent, 'target': target, 'passed': False}); self.save()
            request = self.directory/(label+'-request.json'); receipt = self.directory/(label+'-receipt.json')
            self.atomic(request, q)
            try:
                self.command(label, [self.args.client, '-launch', str(self.directory/'launch.yaml'), '-key', str(self.directory/'operator.pem'),
                    '-endpoint', self.tunnels[agent][1], '-request', str(request), '-receipt', str(receipt)], timeout=310)
            except Exception:
                # Retry only failed initial handshakes; a verified result or a
                # non-idempotent phase is never silently resubmitted.
                if not retry_start or receipt.exists() or time.monotonic() >= deadline: raise
                self.open_tunnel(agent)
                time.sleep(3); continue
            proof = json.loads(receipt.read_text())
            need(proof.get('native_tdx_armtls_verified') and proof.get('image_and_launch_verified') and proof['result']['passed'], 'verified guest assertion failed')
            result = proof['result']; self.state['phases'][-1].update(passed=True, seconds=result['seconds'])
            ca = result.get('checks', {}).get('ca_fingerprint')
            if ca:
                need(not self.state.get('ca') or self.state['ca'] == ca, 'CA changed between independently verified guests')
                self.state['ca'] = ca
            self.save(); self.event('guest-phase-passed', operation=operation, agent=agent, target=target, seconds=round(result['seconds'], 3))
            return result.get('checks', {})

    def artifacts(self):
        self.state['images'] = {}; self.state['archives'] = {}
        for variant, directory in [('a', self.args.image_a), ('b', self.args.image_b)]:
            p = Path(directory); m = json.loads((p/'manifest.json').read_text()); td = m['tdx']
            need(m['version'] == 3 and m['build']['platform'] == 'tdx' and m['build']['memory'] == '4G', 'native TDX 4G artifact required')
            for entry in [m['outputs']['disk_image'], m['outputs']['uki'], td['firmware']]:
                actual = self.native.digest(p/entry['path']); need(actual == entry['sha256'], 'artifact hash differs')
            need(all(len(td[k]) == 96 and set(td[k]) != {'0'} for k in ('mrtd', 'rtmr1', 'rtmr2')), 'full measured TDX tuple required')
            self.state['images'][variant] = {'directory': str(p), 'pins': td, 'disk_sha256': m['outputs']['disk_image']['sha256']}
            archive = p/('three-host-transfer.tar.gz')
            if not archive.exists():
                with tarfile.open(archive, 'w:gz', compresslevel=1) as tar: tar.add(p/'disk.raw', arcname='disk.img', recursive=False)
            self.state['archives'][variant] = str(archive)
        need(self.state['images']['a']['disk_sha256'] != self.state['images']['b']['disk_sha256'], 'distinct measured images required')
        self.save()

    def launch(self):
        import yaml
        self.command('operator-key', ['openssl', 'ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', str(self.directory/'operator.pem')])
        pub = self.command('operator-public', ['openssl', 'ec', '-in', str(self.directory/'operator.pem'), '-pubout']).decode()
        _, namespace = self.kube.call('GET', '/api/v1/namespaces/'+NS)
        subnet_names = namespace['metadata'].get('annotations', {}).get('ovn.kubernetes.io/logical_switch', '').split(',')
        _, subnets = self.kube.call('GET', '/apis/kubeovn.io/v1/subnets')
        subnets = [s for s in subnets['items'] if NS in s['spec'].get('namespaces', []) or s['metadata']['name'] in subnet_names]
        need(len(subnets) == 1, 'one explicit namespace subnet required')
        cidrs = [s.strip() for s in subnets[0]['spec']['cidrBlock'].split(',') if ':' not in s]
        need(len(cidrs) == 1, 'one observed guest IPv4 subnet required')
        images = []
        for v in ['a', 'b']:
            td = self.state['images'][v]['pins']; images.append({'name': 'guest-'+v, 'mrtd': td['mrtd'], 'rtmr': [None, td['rtmr1'], td['rtmr2'], None]})
        config = {'schemaVersion': 'c8s-cds/v1', 'clusterID': self.run, 'operatorPublicKeys': pub,
            'workloads': json.dumps({'schema': 'c8s.allowlist/v1', 'workloads': {'attestation-api': {'containers': [{'digest': 'sha256:'+'11'*32, 'command': {'policy': 'any'}, 'args': {'policy': 'any'}}]}}}),
            'nodes': json.dumps({'schema_version': '1', 'tee': 'tdx', 'measurements': images}), 'nodeCIDRs': cidrs,
            'ha': {'replicas': [f'{self.run}-g{i}.{NS}.svc.cluster.local' for i in range(3)], 'voters': 3}}
        if self.args.backend != 'raft':
            key = secrets.token_bytes(32); origin = f'https://{self.run}-api.{NS}.svc.cluster.local:9443'
            config['ha']['objectWALPilot'] = {'bucket': 'inline-only', 'region': 'fixture', 'prefix': self.run, 'endpoint': origin,
                'pathStyle': True, 'keySHA256': hashlib.sha256(key).hexdigest(), 'metadataEndpoint': origin,
                'metadataRootCA': (self.directory/'api-ca.pem').read_text(), 'directState': True, 'atomicOperatorWrites': True}
            self.atomic(self.directory/'provision.json', {'key': base64.b64encode(key).decode(), 'metadata_token': self.token,
                'credentials': {'access_key_id': 'synthetic', 'secret_access_key': 'test-only'}})
        path = self.directory/'launch.yaml'; path.write_text(yaml.safe_dump(config, sort_keys=True)); path.chmod(0o600)
        self.state['launch_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest(); self.save()
        return path

    def exercise(self):
        self.artifacts()
        if self.args.backend == 'raft':
            need(not self.state['resources'], 'fresh journal required'); baseline = self.health(capture=True)
            self.state['nodes'] = [{'name': n, 'uid': baseline[n]['uid']} for n in self.args.nodes]; self.save()
            _, admin = self.kube.call('GET', '/apis/policy.networking.k8s.io/v1alpha1/adminnetworkpolicies')
            need(all(x['spec']['priority'] != 89 for x in admin['items']), 'priority 89 occupied')
            need(any(x['metadata']['name'] == 'cloud-project-boundaries' and x['spec']['priority'] == 90 for x in admin['items']), 'project boundary differs')
            self.create(guests.admin(self.run, self.state['expires']))
        else:
            self.etcd = self.setup()
        launch = self.launch(); pending = {}
        for slot in range(3):
            for item in guests.network(self.run, slot, self.state['expires']): self.create(item)
            for variant in ['a', 'b']:
                items, vm = self.render_guest(slot, variant, launch); self.populate(items, variant); pending[slot, variant] = vm
        for slot in range(3):
            self.boot_guest(pending[slot, 'a'], slot, 'a'); self.phase(slot, 'init', slot, retry_start=True)
            self.phase(slot, 'provision', slot)
        self.phase(0, 'seed'); self.phase(0, 'roll-safe')
        for slot in [1, 2]: self.phase(slot, 'attach', slot)
        self.phase(0, 'burst')
        # Isolate the actual Raft leader (or one stateless direct-state guest).
        statuses = self.phase(0, 'status')['replicas']
        lost = next((i for i, v in enumerate(statuses) if v['status'].get('state') == 'Leader'), 2) if self.args.backend == 'raft' else 2
        observer = (lost+1)%3
        self.phase(observer, 'prepare', lost); self.phase(lost, 'prepare', lost)
        self.isolate_guest(lost, True)
        try:
            time.sleep(7)  # release Raft's five-second read lease and OVN propagation
            self.phase(lost, 'refuse', lost)
            self.phase(observer, 'survive', lost)
        finally: self.isolate_guest(lost, False)
        self.phase(observer, 'heal'); self.phase(observer, 'roll-safe')
        self.health()
        # Authority quorum loss. Raft loses two CDS members; current state loses
        # two dedicated metadata members, with CDS guests otherwise healthy.
        self.phase(0, 'prepare', 0)
        if self.etcd:
            for row in self.etcd[1][:2]: self.set_policy(row, True)
        else:
            for slot in [1, 2]: self.isolate_guest(slot, True)
        try:
            if self.etcd: self.wait_no_leader(self.etcd[2])
            else: time.sleep(7)
            self.phase(0, 'refuse', 0)
        finally:
            if self.etcd:
                for row in self.etcd[1][:2]: self.set_policy(row, False)
            else:
                for slot in [1, 2]: self.isolate_guest(slot, False)
        if self.etcd: self.wait_members(self.etcd[2])
        self.phase(0, 'heal'); self.phase(0, 'roll-safe')
        self.phase(0, 'overlap'); self.phase(0, 'revoke')
        self.phase(0, 'prepare'); self.phase(0, 'revoked')
        for slot in [2, 1, 0]:
            observer = 0 if slot != 0 else 1
            self.phase(observer, 'prepare', slot); self.phase(observer, 'roll-safe', slot)
            old = self.guests[slot]; self.tunnels[slot][0].terminate(); self.remove(old)
            self.boot_guest(pending[slot, 'b'], slot, 'b'); self.phase(slot, 'init', slot, retry_start=True)
            self.phase(observer, 'provision', slot); self.phase(observer, 'admit', slot)
            self.phase(observer, 'roll-safe', slot); self.phase(observer, 'revoked', slot)
            self.phase(slot, 'attach', slot)
            self.health()
        self.phase(1, 'retire', 1); self.phase(1, 'prepare', 1); self.phase(1, 'revoked', 1)
        self.state['three_guest_cds_passed'] = True
        self.state['distinct_guest_workers'] = len({x['node_uid'] for x in self.state['guest_placements']})
        need(self.state['distinct_guest_workers'] == 3, 'three independently placed guests required')
        self.health(); self.event('three-host-qualification-passed', backend=self.args.backend)

    def diagnostics(self):
        super().diagnostics()
        for slot, row in self.guests.items():
            try:
                if self.current(row, absent=True) is None: continue
                name = row['item']['metadata']['name']
                # Read a bounded console tail without sending keystrokes.
                with (self.directory/(name+'-console.log')).open('ab') as log:
                    p = subprocess.Popen([self.args.virtctl, '--kubeconfig', self.args.kubeconfig, '-n', NS,
                        'console', name, '--timeout=10s'], stdin=subprocess.DEVNULL, stdout=log, stderr=log)
                    try: p.wait(timeout=15)
                    except subprocess.TimeoutExpired: p.terminate(); p.wait(timeout=5)
            except Exception: pass


def main():
    p = argparse.ArgumentParser(description=__doc__); p.add_argument('action', choices=['run', 'cleanup', 'audit'])
    for name in ['directory', 'kubeconfig', 'kubectl', 'virtctl', 'cloud-helpers', 'tools-image', 'etcd-binary', 'metadata-binary', 'source-tree', 'renderer', 'client', 'image-a', 'image-b']:
        p.add_argument('--'+name, required=True)
    p.add_argument('--backend', required=True, choices=['raft', 'direct-state']); p.add_argument('--nodes', nargs=3, required=True)
    args = p.parse_args(); args.platform = 'tdx'; os.umask(0o077)
    need(len(set(args.nodes)) == 3, 'distinct workers required')
    run = Run(args)
    def interrupted(*_): raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, interrupted)
    if args.action == 'audit':
        paths = set()
        for row in run.state['resources']:
            path = run.resource_path(row['item']); need(path == row['path'], 'audit journal path differs'); paths.add(path)
            if row.get('pv'): paths.add('/api/v1/persistentvolumes/'+row['pv']['name'])
            if row['item']['kind'] == 'VirtualMachine': paths.add(VMI+row['item']['metadata']['name'])
        remaining = [path for path in sorted(paths) if run.kube.call('GET', path, expected=(200, 404))[0] != 404]
        _, pods = run.kube.call('GET', '/api/v1/namespaces/'+NS+'/pods?labelSelector='+urllib.parse.quote(OWNER+'='+run.run))
        remaining += ['owned-pod/'+x['metadata']['name'] for x in pods['items']]
        proof = {'read_only_independent_audit': True, 'resource_paths_checked': len(paths), 'cleanup_verified': not remaining, 'remaining': remaining}
        run.atomic(run.directory/'cleanup-audit.json', proof); need(not remaining, 'owned resources remain'); print('independent cleanup audit passed'); return
    if args.action == 'cleanup': run.cleanup(); return
    try: run.exercise()
    except BaseException as e:
        run.event('qualification-failed', failure=type(e).__name__, detail=str(e)); run.diagnostics(); raise
    finally:
        run.cleanup(); run.health()


if __name__ == '__main__': main()
