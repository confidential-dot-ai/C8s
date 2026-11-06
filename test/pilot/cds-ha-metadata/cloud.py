#!/usr/bin/env python3
"""Owned, bounded HIL1 metadata qualification. No shared rollout or host fault."""
import argparse
import concurrent.futures
import copy
import datetime as dt
import hashlib
import http.client
import importlib.util
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import ssl
import subprocess
import sys
import tarfile
import time
import urllib.parse
from typing import NamedTuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from fixtures import NS, OWNER, COMPONENT, SLOT, render, partition, need

KINDS = {'Pod': ('v1', 'pods'), 'Service': ('v1', 'services'), 'Secret': ('v1', 'secrets'),
         'PersistentVolumeClaim': ('v1', 'persistentvolumeclaims'),
         'NetworkPolicy': ('networking.k8s.io/v1', 'networkpolicies'),
         'AdminNetworkPolicy': ('policy.networking.k8s.io/v1alpha1', 'adminnetworkpolicies')}


class MetadataSetup(NamedTuple):
    members: list
    policies: list
    etcd_urls: list
    member_status: list
    adapters: list
    adapter_urls: list


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def resource_path(item, run):
    m = item['metadata']; kind = item['kind']
    suffixes = {'Pod': r'-(e|a|pop)[0-2]', 'Service': r'-(e[0-2]|api)', 'Secret': r'-(e|a)[0-2]',
                'PersistentVolumeClaim': r'-data[0-2]', 'NetworkPolicy': r'-(e|a)[0-2]', 'AdminNetworkPolicy': ''}
    need(re.fullmatch(r'cds-ha-[0-9a-f]{12}', run) and kind in KINDS and
         m.get('labels', {}).get(OWNER) == run and re.fullmatch(re.escape(run)+suffixes[kind], m['name']), 'foreign fixture')
    version, plural = KINDS[kind]
    need(item['apiVersion'] == version, 'wrong resource version')
    prefix = '/api/v1' if version == 'v1' else '/apis/'+version
    if kind != 'AdminNetworkPolicy':
        need(m.get('namespace') == NS, 'wrong namespace')
        prefix += '/namespaces/'+NS
    else:
        need('namespace' not in m and item['spec']['priority'] == 89, 'wrong admin scope')
    return prefix+'/'+plural+'/'+m['name']


def certificates(run, directory):
    now = dt.datetime.now(dt.timezone.utc)
    def root(name):
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now-dt.timedelta(minutes=5)).not_valid_after(now+dt.timedelta(hours=2))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), True)
            .sign(key, hashes.SHA256()))
        return key, cert
    def issue(root, name, hosts, client=True, loopback=True):
        issuer_key, issuer = root; key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        uses = [x509.ExtendedKeyUsageOID.SERVER_AUTH]
        if client:
            uses.append(x509.ExtendedKeyUsageOID.CLIENT_AUTH)
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now-dt.timedelta(minutes=5)).not_valid_after(now+dt.timedelta(hours=2))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(h) for h in hosts]+([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))] if loopback else [])), False)
            .add_extension(x509.ExtendedKeyUsage(uses), False).sign(issuer_key, hashes.SHA256()))
        return {'tls.crt': cert.public_bytes(serialization.Encoding.PEM),
                'tls.key': key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())}
    etcd, api = root(run+' etcd'), root(run+' API')
    out = {'etcd_ca': etcd[1].public_bytes(serialization.Encoding.PEM), 'api_ca': api[1].public_bytes(serialization.Encoding.PEM),
           'members': [], 'adapters': [], 'client': issue(etcd, run+' client', ['localhost'])}
    for i in range(3):
        out['members'].append(issue(etcd, f'{run}-e{i}', [f'{run}-e{i}.{NS}.svc.cluster.local'], loopback=False))
        out['adapters'].append(issue(api, f'{run}-a{i}', [f'{run}-api.{NS}.svc.cluster.local'], client=False))
    for name, value in {'etcd-ca.pem': out['etcd_ca'], 'api-ca.pem': out['api_ca'],
                        'client.crt': out['client']['tls.crt'], 'client.key': out['client']['tls.key']}.items():
        (directory/name).write_bytes(value); (directory/name).chmod(0o600)
    return out


class Run:
    def __init__(self, args):
        self.args = args; self.directory = Path(args.directory)
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True); self.directory.chmod(0o700)
        self.path = self.directory/'journal.json'
        sys.path.insert(0, args.cloud_helpers)
        import cds_ha_rehearsal as helpers
        self.helpers = helpers
        self.kube = helpers.kube_client(args.kubeconfig)
        self.state = json.loads(self.path.read_text()) if self.path.exists() else {
            'schema_version': 1, 'run': 'cds-ha-'+secrets.token_hex(6), 'resources': [], 'events': [],
            'expires': (dt.datetime.now(dt.timezone.utc)+dt.timedelta(minutes=45)).isoformat(),
            'metadata_ha_passed': False, 'three_guest_cds_passed': False, 'production_ready': False}
        self.run = self.state['run']; self.forwards = []; self.tls_names = {}
        need(self.state['schema_version'] == 1 and re.fullmatch(r'cds-ha-[0-9a-f]{12}', self.run), 'invalid journal')
        self.native = load_module('cds_native_health', Path(__file__).resolve().parents[1]/'cds-sealed-recovery/hardware/run.py')
        self.save()

    def save(self):
        self.helpers.atomic_json(self.path, self.state)

    def event(self, name, **fields):
        value = {'time': dt.datetime.now(dt.timezone.utc).isoformat(), 'event': name, **fields}
        self.state['events'].append(value); self.save(); print(json.dumps(value), flush=True)

    def live(self):
        need(dt.datetime.now(dt.timezone.utc) < dt.datetime.fromisoformat(self.state['expires'])-dt.timedelta(minutes=5), 'cleanup window reached')

    def health(self, capture=False):
        return self.native.Run.health(self, capture)

    def command(self, name, argv, data=None, timeout=90):
        with (self.directory/(name+'.stderr')).open('wb') as err:
            p = subprocess.run(argv, input=data, stdout=subprocess.PIPE, stderr=err, timeout=timeout)
        (self.directory/(name+'.stdout')).write_bytes(p.stdout)
        need(p.returncode == 0, name+' failed; inspect private log')
        return p.stdout

    def kubectl(self, *args):
        return [self.args.kubectl, '--kubeconfig', self.args.kubeconfig, '-n', NS, *args]

    def resource_path(self, item):
        return resource_path(item, self.run)

    def create(self, item):
        self.live(); path = self.resource_path(item)
        code, _ = self.kube.call('GET', path, expected=(200, 404)); need(code == 404, 'refusing existing fixture')
        digest = hashlib.sha256(json.dumps(item, sort_keys=True).encode()).hexdigest()
        item['metadata'].setdefault('annotations', {})['cds.confidential.ai/intent-sha256'] = digest
        row = {'item': item, 'path': path, 'uid': None, 'intent_sha256': digest}; self.state['resources'].append(row)
        self.state['cleanup_verified'] = False; self.save()
        code, current = self.kube.call('POST', path.rsplit('/', 1)[0], item, expected=(201, 500, 502, 503, 504))
        if code != 201:
            code, current = self.kube.call('GET', path, expected=(200, 404))
            need(code == 200, 'create unavailable; intent retained for cleanup')
        need(current['metadata'].get('labels', {}).get(OWNER) == self.run and
             current['metadata'].get('annotations', {}).get('cds.confidential.ai/intent-sha256') == digest, 'create owner/intent mismatch')
        row['uid'] = current['metadata']['uid']; self.save(); return row

    def current(self, row, absent=False):
        need(row['path'] == self.resource_path(row['item']), 'foreign journal path')
        code, value = self.kube.call('GET', row['path'], expected=(200, 404) if absent else (200,))
        if code == 404:
            return None
        need(value['metadata'].get('labels', {}).get(OWNER) == self.run and
             (row['uid'] is None or row['uid'] == value['metadata']['uid']), 'fixture UID or owner changed')
        if row['uid'] is None:
            need(value['metadata'].get('annotations', {}).get('cds.confidential.ai/intent-sha256') == row['intent_sha256'], 'lost-create intent differs')
            row['uid'] = value['metadata']['uid']; self.save()
        return value

    def wait_absent(self, path):
        end = time.monotonic()+150
        while time.monotonic() < end:
            code, _ = self.kube.call('GET', path, expected=(200, 404))
            if code == 404:
                return
            time.sleep(1)
        raise RuntimeError('owned resource removal timed out')

    def remove(self, row):
        if row.get('deleted'):
            return
        current = self.current(row, absent=True)
        if current is not None:
            if row['item']['kind'] == 'PersistentVolumeClaim' and current.get('spec', {}).get('volumeName'):
                name = current['spec']['volumeName']; _, pv = self.kube.call('GET', '/api/v1/persistentvolumes/'+name)
                need(pv['spec']['claimRef']['uid'] == row['uid'] and pv['spec']['persistentVolumeReclaimPolicy'] == 'Delete', 'unexpected owned volume reclaim policy')
                row['pv'] = {'name': name, 'uid': pv['metadata']['uid']}; self.save()
            self.kube.call('DELETE', row['path'], {'apiVersion': 'v1', 'kind': 'DeleteOptions',
                'preconditions': {'uid': row['uid']}, 'propagationPolicy': 'Foreground'}, expected=(200, 202, 404))
            self.wait_absent(row['path'])
        if row.get('pv'):
            self.wait_absent('/api/v1/persistentvolumes/'+row['pv']['name'])
        row['deleted'] = True; self.save()

    def cleanup(self):
        for p, log in self.forwards:
            p.terminate()
            try: p.wait(timeout=5)
            except subprocess.TimeoutExpired: p.kill(); p.wait()
            log.close()
        self.forwards = []; failures = []
        for kind in ['Pod', 'Service', 'NetworkPolicy', 'Secret', 'PersistentVolumeClaim', 'AdminNetworkPolicy']:
            for row in self.state['resources']:
                if row['item']['kind'] == kind:
                    try: self.remove(row)
                    except Exception as error: failures.append(type(error).__name__+': '+str(error))
        self.state['cleanup_verified'] = not failures
        self.event('cleanup', complete=not failures, errors=failures)
        need(not failures, 'cleanup incomplete; retain journal')

    def ready(self, row):
        end = time.monotonic()+120
        while time.monotonic() < end:
            value = self.current(row)
            if any(c['type'] == 'Ready' and c['status'] == 'True' for c in value.get('status', {}).get('conditions', [])):
                need(value['spec']['nodeName'] == row['item']['spec']['nodeSelector']['kubernetes.io/hostname'], 'pod on wrong worker')
                return value
            time.sleep(1)
        raise RuntimeError('owned pod readiness timed out')

    def forward(self, row, remote_port):
        self.current(row)
        with socket.socket() as s:
            s.bind(('127.0.0.1', 0)); port = s.getsockname()[1]
        name = row['item']['metadata']['name']
        log = (self.directory/(name+f'-{remote_port}-forward.log')).open('ab')
        p = subprocess.Popen(self.kubectl('port-forward', 'pod/'+name, f'{port}:{remote_port}', '--address=127.0.0.1'), stdout=log, stderr=log)
        self.forwards.append((p, log))
        end = time.monotonic()+15
        while time.monotonic() < end:
            need(p.poll() is None, 'owned port-forward exited')
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=.5):
                    origin = f'https://127.0.0.1:{port}'
                    service = name if remote_port == 2379 else self.run+'-api'
                    self.tls_names[origin] = f'{service}.{NS}.svc.cluster.local'
                    return origin
            except OSError: time.sleep(.1)
        raise RuntimeError('owned forward did not listen')

    def set_policy(self, row, isolated):
        self.live(); current = self.current(row)
        need(current['spec']['podSelector'] == row['item']['spec']['podSelector'] and
             current['spec']['policyTypes'] == row['item']['spec']['policyTypes'], 'owned policy scope changed')
        target = partition(row['item']) if isolated else row['item']
        patch = [{'op': 'test', 'path': '/metadata/uid', 'value': row['uid']},
                 {'op': 'test', 'path': '/metadata/resourceVersion', 'value': current['metadata']['resourceVersion']},
                 {'op': 'replace', 'path': '/spec/ingress', 'value': target['spec']['ingress']},
                 {'op': 'replace', 'path': '/spec/egress', 'value': target['spec']['egress']}]
        self.kube.call('PATCH', row['path'], patch, headers={'Content-Type': 'application/json-patch+json'})
        row['isolated'] = isolated; self.save()

    def request(self, origin, path, body, etcd=False, timeout=8):
        context = ssl.create_default_context(cafile=str(self.directory/('etcd-ca.pem' if etcd else 'api-ca.pem')))
        if etcd:
            context.load_cert_chain(str(self.directory/'client.crt'), str(self.directory/'client.key'))
        # Only this run's authenticated loopback tunnels are accepted. Preserve
        # the real service DNS name for certificate verification through them.
        url = urllib.parse.urlsplit(origin)
        need(url.scheme == 'https' and url.hostname == '127.0.0.1' and origin in self.tls_names, 'unknown owned tunnel')
        name = self.tls_names[origin]
        class Tunnel(http.client.HTTPSConnection):
            def connect(connection):
                connection.sock = context.wrap_socket(socket.create_connection(('127.0.0.1', url.port), timeout=timeout), server_hostname=name)
        connection = Tunnel(url.hostname, url.port, timeout=timeout, context=context)
        headers = {'Content-Type': 'application/json'}
        if not etcd:
            headers.update({'Authorization': 'Bearer '+self.token, 'X-CDS-Namespace': self.run})
        try:
            connection.request('POST', path, body=json.dumps(body).encode(), headers=headers)
            response = connection.getresponse()
            raw = response.read(2*1024*1024+1); need(len(raw) <= 2*1024*1024, 'oversized fixture response')
            return response.status, json.loads(raw) if raw else None
        except (OSError, http.client.HTTPException): return 0, None
        finally: connection.close()

    def setup(self):
        self.live(); need(not self.state['resources'], 'fresh run required; use cleanup for an existing journal')
        need(self.args.source_tree and re.fullmatch(r'[0-9a-f]{40}', self.args.source_tree), 'frozen source tree required')
        baseline = self.health(capture=True)
        nodes = [{'name': name, 'uid': baseline[name]['uid']} for name in self.args.nodes]
        _, admin = self.kube.call('GET', '/apis/policy.networking.k8s.io/v1alpha1/adminnetworkpolicies')
        need(all(x['spec']['priority'] != 89 for x in admin['items']), 'priority 89 is occupied')
        boundary = next((x for x in admin['items'] if x['metadata']['name'] == 'cloud-project-boundaries'), None)
        need(boundary and boundary['spec']['priority'] == 90, 'shared project boundary differs from audited ordering')
        certs = certificates(self.run, self.directory); self.token = secrets.token_hex(32)
        self.state['nodes'] = nodes; self.state['metadata_source_tree'] = self.args.source_tree
        self.state['etcd_version'] = '3.7.3'; self.save()
        items = render(self.run, nodes, self.args.tools_image, certs, self.state['expires'])
        # Prepare public binaries once, verify exact file hashes after every upload.
        archive = io.BytesIO()
        hashes_expected = {}
        with tarfile.open(fileobj=archive, mode='w:gz') as tar:
            for name, path in [('etcd', self.args.etcd_binary), ('metadata', self.args.metadata_binary)]:
                data = Path(path).read_bytes(); hashes_expected[name] = hashlib.sha256(data).hexdigest()
                info = tarfile.TarInfo('bin/'+name); info.size = len(data); info.mode = 0o755
                tar.addfile(info, io.BytesIO(data))
        self.state['binary_hashes'] = hashes_expected; self.save()
        et = []; policies = []
        for item in items:
            row = self.create(item)
            if item['kind'] == 'Pod' and item['metadata']['labels'][COMPONENT] == 'population':
                self.ready(row); name = item['metadata']['name']; payload = archive.getvalue()
                self.command(name+'-upload', self.kubectl('exec', '-i', name, '--', 'sh', '-c',
                    'head -c "$1" | tar -xz -C /data', 'receive', str(len(payload))), data=payload, timeout=180)
                output = self.command(name+'-hash', self.kubectl('exec', name, '--', 'sha256sum', '/data/bin/etcd', '/data/bin/metadata')).decode()
                need({line.split()[1].rsplit('/', 1)[1]: line.split()[0] for line in output.splitlines()} == hashes_expected, 'uploaded binary differs')
                self.remove(row)
            if item['kind'] == 'Pod' and item['metadata']['labels'][COMPONENT] == 'etcd': et.append(row)
            if item['kind'] == 'NetworkPolicy': policies.append(row)
        for row in et: self.ready(row)
        etcd_urls = [self.forward(row, 2379) for row in et]
        status = self.wait_members(etcd_urls)
        cluster_id = status[0]['header']['cluster_id']
        need(len({s['header']['member_id'] for s in status}) == 3 and all(s['header']['cluster_id'] == cluster_id for s in status), 'etcd member identity mismatch')
        self.state['etcd_cluster_id'] = cluster_id; self.save(); self.event('three-worker-quorum-ready', members=3, distinct_workers=len(set(self.args.nodes)))
        adapters = []
        for item in render(self.run, nodes, self.args.tools_image, certs, self.state['expires'], cluster_id, self.token):
            row = self.create(item)
            if item['kind'] == 'Pod': adapters.append(row)
        for row in adapters: self.ready(row)
        urls = [self.forward(row, 9443) for row in adapters]
        return MetadataSetup(et, policies, etcd_urls, status, adapters, urls)

    def exercise(self):
        et, policies, etcd_urls, status, adapters, urls = self.setup()
        self.check_transactions(urls)
        self.health()
        # Isolate the observed leader with only its own policy. The minority
        # remains reachable through the authenticated Kubernetes tunnel.
        leader = next(i for i, s in enumerate(status) if s['header']['member_id'] == s['leader'])
        self.set_policy(policies[leader], True)
        try:
            self.wait_read(urls[(leader+1)%3])
            self.wait_no_leader([etcd_urls[leader]])
            code, _ = self.request(etcd_urls[leader], '/v3/kv/range', {'key': 'aW5zcGVjdA==', 'serializable': False}, etcd=True)
            need(code != 200, 'partitioned member served a purportedly current read')
            self.state['minority_read_refused'] = True
            self.event('partition-majority-serves-minority-refuses')
        finally:
            self.set_policy(policies[leader], False)
        self.wait_members(etcd_urls); self.health()
        # Quorum loss must reject current reads and new commits everywhere.
        for row in policies[:2]: self.set_policy(row, True)
        try:
            self.wait_no_leader(etcd_urls)
            for url in urls:
                code, _ = self.request(url, '/v1/state/read', {'checks': [{'key': self.key('winner')}]})
                need(code != 200, 'metadata quorum loss served current state')
                code, _ = self.request(url, '/v1/state/commit', self.txn('quorum-lost'))
                need(code not in (204, 412), 'quorum loss claimed a definitive commit result')
            self.state['quorum_loss_failed_closed'] = True
            self.event('quorum-loss-failed-closed')
        finally:
            for row in policies[:2]: self.set_policy(row, False)
        self.wait_members(etcd_urls)
        for url in urls: self.wait_read(url)
        self.verify_acknowledged(urls)
        self.state['acknowledged_state_preserved'] = True
        self.state['metadata_ha_passed'] = True
        self.health(); self.event('metadata-ha-passed', members=3, adapters=3, distinct_workers=3)

    def wait_members(self, urls):
        start = time.monotonic(); end = start+90
        samples = []
        while time.monotonic() < end:
            status = [self.request(u, '/v3/maintenance/status', {}, etcd=True) for u in urls]
            samples.append({'elapsed_seconds': round(time.monotonic()-start, 3), 'members': [
                {'http_status': code, 'leader': s.get('leader') if isinstance(s, dict) else None,
                 'member_id': s.get('header', {}).get('member_id') if isinstance(s, dict) else None}
                for code, s in status]})
            self.helpers.atomic_json(self.directory/'member-status-samples.json', samples)
            if all(code == 200 and s.get('leader') not in (None, '0') for code, s in status) and len({s['leader'] for _, s in status}) == 1:
                self.state.setdefault('quorum_ready_seconds', []).append(round(time.monotonic()-start, 3)); self.save()
                return [s for _, s in status]
            time.sleep(.5)
        raise RuntimeError('three members did not report a leader')

    def diagnostics(self):
        # Exact owned UIDs only. Diagnostic collection never replaces cleanup.
        for row in self.state['resources']:
            if row['item']['kind'] != 'Pod' or row.get('deleted'):
                continue
            try:
                value = self.current(row, absent=True)
                if value is None: continue
                name = row['item']['metadata']['name']
                self.helpers.atomic_json(self.directory/(name+'-status.json'), value.get('status', {}))
                self.command(name+'-diagnostic', self.kubectl('logs', name, '--tail=150', '--timestamps=true'), timeout=15)
            except Exception:
                # Record collection failure without dumping credentials, object
                # contents or an unbounded Kubernetes error into public output.
                self.event('diagnostic-unavailable', component=row['item']['metadata']['labels'].get(COMPONENT))

    def wait_no_leader(self, urls):
        end = time.monotonic()+20
        while time.monotonic() < end:
            status = [self.request(u, '/v3/maintenance/status', {}, etcd=True) for u in urls]
            if all(code == 200 and s.get('leader', '0') == '0' for code, s in status): return
            time.sleep(.5)
        raise RuntimeError('partition was not independently observed by member status')

    @staticmethod
    def key(name): return hashlib.sha256(name.encode()).hexdigest()

    def txn(self, name):
        import base64
        key = self.key(name)
        return {'checks': [{'key': key, 'version': ''}], 'writes': [{'key': key, 'version': '0000000000000001',
            'value': base64.b64encode(hashlib.sha256(('opaque-'+name).encode()).digest()).decode()}]}

    def check_transactions(self, urls):
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(lambda i: self.request(urls[i%3], '/v1/state/commit', self.txn('winner'))[0], range(16)))
        need(results.count(204) == 1 and results.count(412) == 15, 'conditional race did not have one winner')
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(lambda i: self.request(urls[i%3], '/v1/state/commit', self.txn('independent-'+str(i)))[0], range(64)))
        need(all(c == 204 for c in results), 'independent transaction failed')
        self.state['independent_commits'] = 64; self.state['conditional_race_winners'] = 1
        self.event('metadata-transactions-passed', independent_commits=64, conditional_race_winners=1)

    def wait_read(self, url):
        end = time.monotonic()+25
        while time.monotonic() < end:
            code, rows = self.request(url, '/v1/state/read', {'checks': [{'key': self.key('winner')}]})
            if code == 200:
                need(len(rows) == 1 and rows[0]['version'] == '0000000000000001' and rows[0]['value'] == self.txn('winner')['writes'][0]['value'], 'acknowledged state changed')
                return
            time.sleep(.2)
        raise RuntimeError('majority did not serve acknowledged current state')

    def verify_acknowledged(self, urls):
        expected = {self.key(n): self.txn(n)['writes'][0] for n in ['winner']+['independent-'+str(i) for i in range(64)]}
        keys = list(expected)
        for url in urls:
            for start in range(0, len(keys), 16):
                chunk = keys[start:start+16]
                code, rows = self.request(url, '/v1/state/read', {'checks': [{'key': k} for k in chunk]})
                need(code == 200 and rows == [expected[k] for k in chunk], 'acknowledged record was lost or changed')
        self.state['acknowledged_records_verified_per_adapter'] = len(keys)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=['run', 'cleanup'])
    for name in ['directory', 'kubeconfig', 'kubectl', 'cloud-helpers']: p.add_argument('--'+name, required=True)
    for name in ['tools-image', 'etcd-binary', 'metadata-binary', 'source-tree']: p.add_argument('--'+name)
    p.add_argument('--nodes', nargs=3, required=True)
    p.add_argument('--platform', choices=['snp', 'tdx'], default='tdx')
    args = p.parse_args(); os.umask(0o077)
    run = Run(args)
    def interrupted(signum, frame): raise InterruptedError('owned run interrupted')
    signal.signal(signal.SIGTERM, interrupted); signal.signal(signal.SIGINT, interrupted)
    try:
        if args.action == 'run': run.exercise()
    except BaseException:
        run.diagnostics()
        raise
    finally:
        run.cleanup()
        if 'nodes_before' in run.state: run.health()


if __name__ == '__main__': main()
