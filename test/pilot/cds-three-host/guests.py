"""Only owned CDS guests and narrowly scoped network resources."""
import copy
import re
from fixtures import NS, OWNER, COMPONENT, SLOT, need, selector, meta, dns_rule
from cloud import resource_path as metadata_path


def resource_path(item, run):
    m = item['metadata']; name = m['name']; kind = item['kind']
    suffix = {'VirtualMachine': r'-g[0-2]-[ab]', 'Secret': r'-g[0-2]-[ab]-opkey',
              'Pod': r'-g[0-2]-[ab]-populate', 'PersistentVolumeClaim': r'-g[0-2]-[ab]-root',
              'Service': r'-g[0-2]', 'NetworkPolicy': r'-g[0-2]'}
    if kind not in suffix or not re.fullmatch(re.escape(run)+suffix[kind], name):
        return metadata_path(item, run)
    need(re.fullmatch(r'cds-ha-[0-9a-f]{12}', run) and m.get('namespace') == NS and
         m.get('labels', {}).get(OWNER) == run, 'foreign guest fixture')
    version, plural = {'VirtualMachine': ('kubevirt.io/v1', 'virtualmachines'),
        'Secret': ('v1', 'secrets'), 'Pod': ('v1', 'pods'), 'PersistentVolumeClaim': ('v1', 'persistentvolumeclaims'),
        'Service': ('v1', 'services'), 'NetworkPolicy': ('networking.k8s.io/v1', 'networkpolicies')}[kind]
    need(item['apiVersion'] == version, 'wrong guest resource version')
    return ('/api/v1' if version == 'v1' else '/apis/'+version)+'/namespaces/'+NS+'/'+plural+'/'+name


def admin(run, expires):
    pods = {'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': NS}}, 'podSelector': selector(run)}
    return {'apiVersion': 'policy.networking.k8s.io/v1alpha1', 'kind': 'AdminNetworkPolicy',
        'metadata': {'name': run, 'labels': {OWNER: run}, 'annotations': {'cds.confidential.ai/cleanup-deadline': expires}},
        'spec': {'priority': 89, 'subject': {'pods': pods}, 'egress': [{'name': 'owned-cds-metadata-only', 'action': 'Pass',
            'to': [{'pods': pods}], 'ports': [{'portNumber': {'protocol': 'TCP', 'port': p}} for p in (1019, 2379, 2380, 8443, 8444, 9443)]}]}}


def public_collateral():
    # Native Intel/AMD collateral fetching only, never private service access.
    return {'to': [{'ipBlock': {'cidr': '0.0.0.0/0', 'except': ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '169.254.0.0/16']}}],
            'ports': [{'protocol': 'TCP', 'port': 443}]}


def network(run, slot, expires):
    name = '-g'+str(slot)
    service = {'apiVersion': 'v1', 'kind': 'Service', 'metadata': meta(run, name, 'cds', slot, expires),
        'spec': {'clusterIP': 'None', 'publishNotReadyAddresses': True, 'selector': selector(run, 'cds', slot)['matchLabels'],
                 'ports': [{'name': 'api', 'port': 8443, 'targetPort': 8443}, {'name': 'peer', 'port': 8444, 'targetPort': 8444}]}}
    ports = [{'protocol': 'TCP', 'port': p} for p in (1019, 8443, 8444)]
    tunnel = {'from': [{'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': 'kubevirt'}},
                        'podSelector': {'matchLabels': {'kubevirt.io': 'virt-api'}}}], 'ports': [{'protocol': 'TCP', 'port': 6443}]}
    policy = {'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy', 'metadata': meta(run, name, 'cds', slot, expires),
        'spec': {'podSelector': selector(run, 'cds', slot), 'policyTypes': ['Ingress', 'Egress'],
            'ingress': [tunnel, {'from': [{'podSelector': selector(run, 'cds')}], 'ports': ports}],
            'egress': [dns_rule(), public_collateral(), {'to': [{'podSelector': selector(run, 'cds')}], 'ports': ports},
                       {'to': [{'podSelector': selector(run, 'adapter')}], 'ports': [{'protocol': 'TCP', 'port': 9443}]}]}}
    return [service, policy]


def partition(policy):
    p = copy.deepcopy(policy)
    need(p['metadata']['labels'][COMPONENT] == 'cds' and p['spec']['podSelector'] == selector(
        p['metadata']['labels'][OWNER], 'cds', int(p['metadata']['labels'][SLOT])), 'guest policy scope mismatch')
    p['spec']['ingress'] = p['spec']['ingress'][:1]
    p['spec']['egress'] = [dns_rule(), public_collateral()]
    return p


def validate(items, run, slot, variant, node):
    need(sorted(x['kind'] for x in items) == ['PersistentVolumeClaim', 'Pod', 'Secret', 'VirtualMachine'], 'unexpected SDK guest resources')
    for item in items:
        resource_path(item, run)
        need(item['metadata']['labels'].get(SLOT) == str(slot) and item['metadata']['name'].startswith(f'{run}-g{slot}-{variant}'), 'wrong guest slot')
    vm = next(x for x in items if x['kind'] == 'VirtualMachine'); spec = vm['spec']['template']['spec']
    need(spec['nodeSelector'].get('kubernetes.io/hostname') == node['name'] and
         spec['nodeSelector'].get('cloud.confidential.ai.node-restriction.kubernetes.io/node-uid') == node['uid'], 'worker UID mismatch')
    need(vm['spec']['runStrategy'] == 'Manual' and spec['domain'].get('launchSecurity') == {'tdx': {}}, 'manual TDX guest required')
    need(spec['domain']['cpu']['cores'] == 2 and spec['domain']['memory']['guest'] == '4Gi', 'guest budget differs')
    need(spec['domain']['devices']['interfaces'][0].get('bridge') == {}, 'routable pod bridge required')
    need(all('cloudInit' not in str(v) and 'hostDisk' not in v for v in spec['volumes']), 'host disk or cloud-init forbidden')
    need(all(vm['spec']['template']['metadata']['labels'].get(k) == v for k, v in selector(run, 'cds', slot)['matchLabels'].items()), 'guest labels differ')
    return vm
