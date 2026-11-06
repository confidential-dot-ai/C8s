#!/usr/bin/env python3
"""Sequential Raft/current-state qualification on three owned TDX guests."""
import argparse
import base64
import copy
import datetime as dt
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import ssl
import subprocess
import sys
import time
import urllib.parse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'cds-ha-metadata'))
import cloud as metadata
from fixtures import NS, OWNER, COMPONENT, SLOT, need
import guests
import transfer
import egress
import console
import faults
from api import ReadBackoff

VMI = '/apis/kubevirt.io/v1/namespaces/'+NS+'/virtualmachineinstances/'


def policy_applied(result):
    delivered = result.get('checks', {}).get('delivered', {})
    need(not delivered.get('refused') and not delivered.get('held') and
         delivered.get('applied_version', 0) > 0, 'image policy decree was not applied')


def archive_image(directory):
    # GNU sparse metadata avoids sending/decompressing the large zero regions
    # of the verified raw disk through a short-idle-timeout exec proxy. The
    # receiver still checks the SHA-256 of the complete reconstructed disk.
    directory = Path(directory)
    archive = directory/'three-host-sparse-transfer.tar.gz'
    if not archive.exists():
        partial = directory/('transfer-'+secrets.token_hex(8)+'.partial')
        try:
            with partial.open('xb') as output:
                subprocess.run(['tar', '--sparse', '--format=posix', '--transform=s,^disk.raw$,disk.img,',
                    '-I', 'gzip -1', '-cf', '-', '-C', str(directory), 'disk.raw'], stdout=output, check=True, timeout=180)
            partial.replace(archive)
        finally:
            if partial.exists(): partial.unlink()
    return archive


class Run(metadata.Run):
    def __init__(self, args):
        super().__init__(args)
        self.kube.opener = ReadBackoff(self.kube.opener, lambda attempt, delay, method, kind:
            self.event('kube-request-backpressure', attempt=attempt, delay_seconds=delay, method=method, retry_kind=kind))
        if not self.state['resources']:
            self.state['expires'] = (dt.datetime.now(dt.timezone.utc)+dt.timedelta(minutes=75)).isoformat()
            self.state['backend'] = args.backend
            self.state['three_guest_cds_passed'] = False
            self.state['phases'] = []
            self.save()
        need(self.state['backend'] == args.backend, 'backend differs from journal')
        self.guests = {}; self.tunnels = {}; self.consoles = {}; self.etcd = None
        self.metadata_status_forwards = {}; self.metadata_members = {}
        self.atomic = self.helpers.atomic_json

    def resource_path(self, item): return guests.resource_path(item, self.run)

    def command(self, name, argv, data=None, timeout=90):
        # The native upload helper retries read-only completion probes on
        # RuntimeError. Preserve that interface across the metadata runner.
        try: return super().command(name, argv, data=data, timeout=timeout)
        except ValueError as error: raise RuntimeError(str(error)) from error

    def create(self, item):
        if item['kind'] == 'AdminNetworkPolicy':
            need(item['metadata']['name'] == self.run, 'foreign admin fixture')
            item = guests.admin(self.run, self.state['expires'])
        return super().create(item)

    def forward(self, row, remote_port):
        origin = super().forward(row, remote_port)
        if remote_port == 2379:
            self.metadata_status_forwards[origin] = self.forwards[-1]
        return origin

    def refresh_metadata_observers(self):
        # Image preparation can outlive the API proxy's idle tunnels. Replace
        # only owned, read-only member observers before injecting the fault.
        members, policies, urls = self.etcd
        need(len(members) == len(urls) == 3, 'three owned metadata observers required')
        for url in urls:
            handle = self.metadata_status_forwards.pop(url)
            process, log = handle
            process.terminate()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired: process.kill(); process.wait()
            log.close(); self.forwards.remove(handle); self.tls_names.pop(url)
        urls = [self.forward(row, 2379) for row in members]
        self.etcd = members, policies, urls
        status = self.wait_members(urls)
        identities = [s.get('header', {}).get('member_id') for s in status]
        need(len(set(identities)) == 3 and all(i not in (None, '', '0') for i in identities) and
             all(s['header'].get('cluster_id') == self.state['etcd_cluster_id'] for s in status),
             'refreshed metadata member identity differs')
        self.metadata_members = dict(zip(urls, identities))
        self.event('metadata-status-observers-refreshed', members=3)

    def wait_no_leader(self, urls):
        need(len(urls) == 3 and set(urls) == set(self.metadata_members),
             'verified metadata observers required')
        start = time.monotonic(); end = start+20; samples = []
        while time.monotonic() < end:
            members = []
            for slot, url in enumerate(urls):
                remaining = end-time.monotonic()
                if remaining <= 0: break
                code, status = self.request(url, '/v3/maintenance/status', {}, etcd=True,
                                            timeout=min(8, remaining))
                status = status if isinstance(status, dict) else {}
                header = status.get('header', {})
                header = header if isinstance(header, dict) else {}
                members.append({'slot': slot, 'http_status': code, 'leader': status.get('leader', '0') if code == 200 else None,
                                'member_id': header.get('member_id'), 'cluster_id': header.get('cluster_id')})
            samples.append({'elapsed_seconds': round(time.monotonic()-start, 3), 'members': members})
            self.atomic(self.directory/'metadata-quorum-loss-samples.json', samples)
            if time.monotonic() <= end and len(members) == 3 and all(s['http_status'] == 200 and s['leader'] == '0' and
                    s['member_id'] == self.metadata_members[urls[s['slot']]] and
                    s['cluster_id'] == self.state['etcd_cluster_id'] for s in members):
                self.event('metadata-quorum-loss-observed', members=3)
                return
            time.sleep(min(.5, max(0, end-time.monotonic())))
        raise RuntimeError('partition was not independently observed by member status')

    def cleanup(self):
        failures = []
        for row in self.state['resources']:
            if row['item']['kind'] == 'VirtualMachine':
                try: self.remove(row)
                except Exception as error: failures.append(type(error).__name__+': '+str(error))
        try: super().cleanup()
        except Exception as error: failures.append(type(error).__name__+': '+str(error))
        for capture in self.consoles.values():
            try: capture.close()
            except Exception as error: failures.append(type(error).__name__+': '+str(error))
        self.consoles = {}
        for row in self.state['resources']:
            if row['item']['kind'] != 'Namespace': continue
            try:
                need(all(r.get('deleted') for r in self.state['resources'] if r['item']['metadata'].get('namespace') == egress.NAMESPACE),
                     'collateral namespace still has uncleaned journal children')
                code, remaining = self.kube.call('GET', '/api/v1/namespaces/'+egress.NAMESPACE+'/pods', expected=(200, 404))
                need(code == 404 or not remaining['items'], 'collateral namespace has unrecorded pods')
                self.remove(row)
            except Exception as error: failures.append(type(error).__name__+': '+str(error))
        if failures:
            self.state['cleanup_verified'] = False; self.save()
            self.event('guest-cleanup-incomplete', errors=failures)
            raise RuntimeError('owned guest cleanup incomplete; retain journal')

    def remove(self, row):
        super().remove(row)
        if row['item']['kind'] == 'VirtualMachine':
            self.wait_absent(VMI+row['item']['metadata']['name'])
            capture = self.consoles.pop(row['item']['metadata']['name'], None)
            if capture: capture.close()

    def proxy_kubectl(self, *args):
        return [self.args.kubectl, '--kubeconfig', self.args.kubeconfig, '-n', egress.NAMESPACE, *args]

    def setup_proxy(self):
        need(self.args.collateral_proxy_binary, 'frozen collateral proxy binary required')
        _, subnet = self.kube.call('GET', '/apis/kubeovn.io/v1/subnets/cloud-infra')
        _, guests_subnet = self.kube.call('GET', '/apis/kubeovn.io/v1/subnets/cloud-guests')
        need(subnet['spec'].get('natOutgoing') is True and subnet['spec'].get('default') is True and
             subnet['spec'].get('vpc') == guests_subnet['spec'].get('vpc') and
             any(c['type'] == 'Ready' and c['status'] == 'True' for c in subnet['status']['conditions']),
             'existing default outbound subnet is unavailable')
        for item in egress.render(self.run, self.state['nodes'][0], self.args.tools_image, self.state['expires']):
            row = self.create(item)
        end = time.monotonic()+120
        while time.monotonic() < end:
            live = self.current(row)
            if any(x.get('state', {}).get('running') for x in live.get('status', {}).get('containerStatuses', [])): break
            time.sleep(1)
        else: raise RuntimeError('collateral population container did not start')
        name = row['item']['metadata']['name']; binary = Path(self.args.collateral_proxy_binary)
        need(0 < binary.stat().st_size <= transfer.CHUNK, 'bounded collateral binary required')
        digest = self.native.digest(binary); token = secrets.token_hex(16)
        class Receiver:
            def __getattr__(_, key): return getattr(self, key)
            def kubectl(_, *args): return self.proxy_kubectl(*args)
        with binary.open('rb') as data:
            transfer.receive(Receiver(), 'collateral-binary', name,
                transfer.chunk_receiver(binary.stat().st_size, digest, '/tools/proxy.new', token),
                '/tools/proxy.new.complete', token, data, 45)
        self.command('collateral-install', self.proxy_kubectl('exec', name, '--', 'sh', '-ec',
            'chmod 755 /tools/proxy.new; mv /tools/proxy.new /tools/proxy'))
        self.ready(row)
        self.state['collateral_proxy_binary_sha256'] = digest; self.save()
        with socket.socket() as sock: sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
        log = (self.directory/'collateral-forward.log').open('ab')
        process = subprocess.Popen(self.proxy_kubectl('port-forward', 'pod/'+name, f'{port}:3128', '--address=127.0.0.1'), stdout=log, stderr=log)
        self.forwards.append((process, log))
        end = time.monotonic()+15
        while time.monotonic() < end:
            need(process.poll() is None, 'collateral forward exited')
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=.5): break
            except OSError: time.sleep(.1)
        else: raise RuntimeError('collateral forward did not listen')
        connection = http.client.HTTPSConnection('127.0.0.1', port, timeout=20, context=ssl.create_default_context())
        connection.set_tunnel('api.trustedservices.intel.com', 443)
        try:
            connection.request('GET', '/sgx/certification/v4/pckcrl?ca=platform')
            response = connection.getresponse(); body = response.read(1024*1024+1)
            need(response.status == 200 and 0 < len(body) <= 1024*1024, 'Intel collateral through owned proxy unavailable')
        finally: connection.close()
        self.state['collateral_proxy_passed'] = True
        self.event('collateral-proxy-tls-check-passed', response_bytes=len(body))

    def isolate_guest(self, slot, isolated):
        row = next(r for r in self.state['resources'] if r['item']['kind'] == 'NetworkPolicy' and r['item']['metadata']['name'] == f'{self.run}-g{slot}')
        self.live(); current = self.current(row)
        need(current['spec']['podSelector'] == row['item']['spec']['podSelector'], 'guest policy scope changed')
        target = guests.partition(row['item']) if isolated else row['item']
        patch = [{'op': 'test', 'path': '/metadata/uid', 'value': row['uid']},
                 {'op': 'test', 'path': '/metadata/resourceVersion', 'value': current['metadata']['resourceVersion']},
                 {'op': 'replace', 'path': '/spec/ingress', 'value': target['spec']['ingress']},
                 {'op': 'replace', 'path': '/spec/egress', 'value': target['spec']['egress']}]
        _, updated = self.kube.call('PATCH', row['path'], patch, headers={'Content-Type': 'application/json-patch+json'})
        need(updated['metadata']['uid'] == row['uid'] and
             all(updated['spec'][k] == target['spec'][k] for k in ('podSelector', 'ingress', 'egress')),
             'guest isolation policy update differs')
        row['isolated'] = isolated; self.save()
        self.event('guest-isolation-policy-updated', slot=slot, isolated=isolated,
                   resource_version=updated['metadata']['resourceVersion'])

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
        # Short framed chunks avoid the streaming proxy's idle timeout. Each
        # chunk and the assembled archive are checked by the receiver, then
        # the complete reconstructed disk is independently checked below.
        archive = Path(self.state['archives'][variant])
        link = self.directory/('image-'+variant+'.tar.gz')
        if not link.exists(): link.symlink_to(archive)
        transfer.upload(self, name, link, '/rootdisk')
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
        self.start_console(row)
        self.open_tunnel(slot)

    def start_console(self, row, resume=False):
        self.current(row)
        name = row['item']['metadata']['name']
        _, vmi = self.kube.call('GET', VMI+name)
        expected = next(p['vmi_uid'] for p in self.state['guest_placements'] if p['vm_uid'] == row['uid'])
        need(vmi['metadata']['uid'] == expected, 'console guest identity changed')
        for attempt in range(2):
            capture = console.Capture([self.args.virtctl, '--kubeconfig', self.args.kubeconfig,
                '-n', NS, 'console', name, '--timeout=1'], self.directory/(name+'-live-console.log'), resume=resume or attempt > 0)
            self.consoles[name] = capture
            try:
                capture.wait_connected()
                return
            except RuntimeError:
                capture.close(); self.consoles.pop(name)
                if attempt == 1: raise
                self.current(row)
                _, again = self.kube.call('GET', VMI+name)
                need(again['metadata']['uid'] == expected, 'console guest identity changed')

    def ensure_consoles(self):
        for row in self.guests.values():
            name = row['item']['metadata']['name']
            capture = self.consoles[name]
            if capture.process.poll() is not None:
                capture.close(); self.consoles.pop(name)
                self.start_console(row, resume=True)
                self.event('console-reconnected', guest=name)

    def open_tunnel(self, slot):
        row = self.guests[slot]; faults.current_guest(self, slot)
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
        self.ensure_consoles()
        need(self.tunnels[agent][0].poll() is None, 'VM tunnel exited')
        q = {'operation': operation, 'target': target}
        if operation == 'init':
            q['operator_key'] = base64.b64encode((self.directory/'operator.pem').read_bytes()).decode()
            if self.args.backend != 'raft': q['provision'] = json.loads((self.directory/'provision.json').read_text())
        deadline = time.monotonic()+(180 if retry_start else 310)
        tunnel_restarts = 0
        while True:
            label = f'{len(self.state["phases"]):03}-{operation}-g{agent}'
            self.state['phases'].append({'label': label, 'operation': operation, 'agent': agent, 'target': target, 'passed': False}); self.save()
            request = self.directory/(label+'-request.json'); receipt = self.directory/(label+'-receipt.json')
            self.atomic(request, q)
            try:
                # A failed early virtctl dial can leave its accepted local
                # socket open. Bound each initial attempt so that the existing
                # three-minute startup budget can actually retry its tunnel.
                attempt_timeout = min(30 if retry_start else 310, max(1, deadline-time.monotonic()))
                argv = [self.args.client, '-launch', str(self.directory/'launch.yaml'), '-key', str(self.directory/'operator.pem'),
                        '-endpoint', self.tunnels[agent][1], '-request', str(request), '-receipt', str(receipt)]
                with (self.directory/(label+'.stderr')).open('wb') as err:
                    completed = subprocess.run(argv, stdout=subprocess.PIPE, stderr=err, timeout=attempt_timeout)
                (self.directory/(label+'.stdout')).write_bytes(completed.stdout)
                self.state['phases'][-1]['client_exit_code'] = completed.returncode
                self.save()
                need(completed.returncode == 0, label+' failed; inspect private log')
            except Exception:
                # Exit 75 is emitted only for a typed TLS timeout before HTTP
                # dispatch. Replace the broken virtctl listener before retrying;
                # one restart shares the original phase deadline.
                if self.state['phases'][-1].get('client_exit_code') == 75 and not receipt.exists():
                    self.state['phases'][-1]['not_dispatched'] = True; self.save()
                    if (retry_start or tunnel_restarts == 0) and time.monotonic() < deadline:
                        tunnel_restarts += 1
                        self.event('guest-control-tunnel-restart', operation=operation, agent=agent)
                        self.open_tunnel(agent)
                        time.sleep(3); continue
                    raise
                # Initialization is idempotent. No other uncertain phase or
                # verified assertion failure is resubmitted.
                if not retry_start or receipt.exists() or time.monotonic() >= deadline: raise
                self.open_tunnel(agent)
                time.sleep(3); continue
            proof = json.loads(receipt.read_text())
            need(proof.get('native_tdx_armtls_verified') and proof.get('image_and_launch_verified') and proof['result']['passed'], 'verified guest assertion failed')
            retries = proof.get('pre_dispatch_handshake_retries', 0)
            need(type(retries) is int and retries in (0, 1), 'invalid control handshake retry count')
            if retries:
                self.state['phases'][-1]['pre_dispatch_handshake_retries'] = retries
                self.event('guest-control-handshake-retried', operation=operation, agent=agent, retries=retries)
            result = proof['result']
            if operation in ('overlap', 'retire'):
                policy_applied(result)
            self.state['phases'][-1].update(passed=True, seconds=result['seconds'])
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
            archive = archive_image(p)
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
        self.setup_proxy()
        launch = self.launch(); pending = {}
        for slot in range(3):
            for item in guests.network(self.run, slot, self.state['expires']): self.create(item)
            items, vm = self.render_guest(slot, 'a', launch); self.populate(items, 'a')
            self.boot_guest(vm, slot, 'a'); self.phase(slot, 'init', slot, retry_start=True)
            self.phase(slot, 'startup', slot)
            self.phase(slot, 'provision', slot)
        self.phase(0, 'seed'); self.phase(0, 'roll-safe')
        for slot in [1, 2]: self.phase(slot, 'attach', slot)
        self.phase(0, 'burst')
        # Establish the unchanged initial workload before copying replacement
        # disks. Faults still wait for all three independently verified B disks.
        for slot in range(3):
            items, vm = self.render_guest(slot, 'b', launch); self.populate(items, 'b'); pending[slot, 'b'] = vm
        # Isolate the actual Raft leader (or one stateless direct-state guest).
        statuses = self.phase(0, 'status')['replicas']
        lost = faults.raft_leader(statuses) if self.args.backend == 'raft' else 2
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
        # A policy update alone does not prove that existing flows stopped.
        # Pause two owned Raft VMIs and observe both Paused conditions before
        # exhausting the read lease. Retain their memory for recovery.
        if not self.etcd: faults.raft_leader(self.phase(0, 'status')['replicas'])
        self.phase(0, 'prepare', 0)
        if self.etcd:
            self.refresh_metadata_observers()
            try:
                for row in self.etcd[1][:2]: self.set_policy(row, True)
                self.wait_no_leader(self.etcd[2])
                self.phase(0, 'refuse', 0)
            finally:
                for row in self.etcd[1][:2]: self.set_policy(row, False)
            self.wait_members(self.etcd[2])
        else:
            with faults.paused_guests(self, [1, 2]):
                time.sleep(7)
                self.phase(0, 'refuse', 0)
        self.phase(0, 'heal'); self.phase(0, 'roll-safe')
        self.phase(0, 'overlap'); self.phase(0, 'revoke')
        self.phase(0, 'prepare'); self.phase(0, 'revoked')
        for slot in [2, 1, 0]:
            observer = 0 if slot != 0 else 1
            self.phase(observer, 'prepare', slot); self.phase(observer, 'roll-safe', slot)
            old = self.guests[slot]; self.tunnels[slot][0].terminate(); self.remove(old)
            self.boot_guest(pending[slot, 'b'], slot, 'b'); self.phase(slot, 'init', slot, retry_start=True)
            self.phase(slot, 'startup', slot)
            self.phase(observer, 'provision', slot)
            # Current-state replicas recover after attested provisioning; only
            # the Raft control has membership admission.
            if self.args.backend == 'raft': self.phase(observer, 'admit', slot)
            self.phase(observer, 'roll-safe', slot); self.phase(observer, 'revoked', slot)
            self.phase(slot, 'attach', slot)
            self.health()
        self.phase(1, 'retire', 1); self.phase(1, 'prepare', 1); self.phase(1, 'revoked', 1)
        self.state['three_guest_cds_passed'] = True
        self.state['distinct_guest_workers'] = len({x['node_uid'] for x in self.state['guest_placements']})
        need(self.state['distinct_guest_workers'] == 3, 'three independently placed guests required')
        self.health(); self.event('three-host-qualification-passed', backend=self.args.backend)

    def inspect_backends(self):
        # Fixed read-only phases, never a replay of the failed workload. Keep
        # their receipts separate from qualification results and bound each
        # probe so unavailable guests cannot prevent ordinary cleanup.
        for slot in sorted(self.guests):
            try:
                self.open_tunnel(slot)  # validates the exact owned VM/VMI
                label = 'diagnostic-status-g'+str(slot)
                request = self.directory/(label+'-request.json')
                self.atomic(request, {'operation': 'status', 'target': slot})
                self.command(label, [self.args.client, '-launch', str(self.directory/'launch.yaml'),
                    '-key', str(self.directory/'operator.pem'), '-endpoint', self.tunnels[slot][1],
                    '-request', str(request), '-receipt', str(self.directory/(label+'-receipt.json'))], timeout=25)
                self.event('guest-status-diagnostic-captured', slot=slot)
            except Exception:
                self.event('guest-status-diagnostic-unavailable', slot=slot)
        if self.etcd:
            samples = []
            for slot, url in enumerate(self.etcd[2]):
                try:
                    code, status = self.request(url, '/v3/maintenance/status', {}, etcd=True, timeout=5)
                except Exception:
                    code, status = 0, None
                samples.append({'slot': slot, 'http_status': code, 'status': status})
            self.atomic(self.directory/'failure-member-status.json', samples)

    def diagnostics(self):
        # A console can disconnect during a long phase. Reconnect only that
        # same owned incarnation before fixed status requests produce new logs.
        try: self.ensure_consoles()
        except Exception: self.event('diagnostic-console-reconnect-unavailable')
        try: self.inspect_backends()
        except Exception: self.event('backend-status-diagnostic-unavailable')
        super().diagnostics()
        # The live tail already contains the failed phase. Avoid opening a
        # second console, which could disconnect the active read-only capture.
        for slot, row in self.guests.items():
            try:
                if self.current(row, absent=True) is None: continue
                name = row['item']['metadata']['name']
                if name in self.consoles: continue
                capture = console.Capture([self.args.virtctl, '--kubeconfig', self.args.kubeconfig, '-n', NS,
                    'console', name, '--timeout=1'], self.directory/(name+'-fallback-console.log'))
                try: time.sleep(5)
                finally: capture.close()
            except Exception: pass


def main():
    p = argparse.ArgumentParser(description=__doc__); p.add_argument('action', choices=['run', 'cleanup', 'audit', 'egress-check'])
    for name in ['directory', 'kubeconfig', 'kubectl', 'virtctl', 'cloud-helpers', 'tools-image', 'etcd-binary', 'metadata-binary', 'source-tree', 'renderer', 'client', 'image-a', 'image-b']:
        p.add_argument('--'+name, required=True)
    p.add_argument('--backend', required=True, choices=['raft', 'direct-state']); p.add_argument('--nodes', nargs=3, required=True)
    p.add_argument('--collateral-proxy-binary')
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
        _, pods = run.kube.call('GET', '/api/v1/pods?labelSelector='+urllib.parse.quote(OWNER+'='+run.run))
        remaining += ['owned-pod/'+x['metadata']['name'] for x in pods['items']]
        proof = {'read_only_independent_audit': True, 'resource_paths_checked': len(paths), 'cleanup_verified': not remaining, 'remaining': remaining}
        run.atomic(run.directory/'cleanup-audit.json', proof); need(not remaining, 'owned resources remain'); print('independent cleanup audit passed'); return
    if args.action == 'cleanup': run.cleanup(); return
    try:
        if args.action == 'egress-check':
            need(not run.state['resources'], 'fresh egress check required')
            baseline = run.health(capture=True)
            run.state['nodes'] = [{'name': n, 'uid': baseline[n]['uid']} for n in args.nodes]; run.save()
            run.setup_proxy()
        else: run.exercise()
    except BaseException as e:
        run.event('qualification-failed', failure=type(e).__name__, detail=str(e)); run.diagnostics(); raise
    finally:
        run.cleanup()
        if 'nodes_before' in run.state and 'vmis_before' in run.state:
            run.health()
        else:
            run.event('health-baseline-unavailable')


if __name__ == '__main__': main()
