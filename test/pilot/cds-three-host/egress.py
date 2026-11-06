"""An owned collateral-only proxy on the existing default outbound subnet."""
import re
import copy
from fixtures import NS, OWNER, COMPONENT, need, selector, dns_rule, pod

NAMESPACE = 'cds-three-host-egress'
ORIGIN = 'http://collateral.'+NAMESPACE+'.svc.cluster.local:3128'
PUBLIC_EXCEPT = ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
    '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.88.99.0/24', '192.168.0.0/16',
    '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4']


def destination(run):
    return {'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': NAMESPACE, OWNER: run}},
            'podSelector': selector(run, 'collateral')}


def rule(run):
    return {'to': [destination(run)], 'ports': [{'protocol': 'TCP', 'port': 3128}]}


def path(item, run):
    m = item['metadata']; kind = item['kind']
    need(re.fullmatch(r'cds-ha-[0-9a-f]{12}', run) and m.get('labels', {}).get(OWNER) == run, 'foreign collateral fixture')
    if kind == 'Namespace':
        need(item['apiVersion'] == 'v1' and m['name'] == NAMESPACE and 'namespace' not in m, 'foreign collateral namespace')
        return '/api/v1/namespaces/'+NAMESPACE
    versions = {'Pod': ('v1', 'pods', run+'-proxy'), 'Service': ('v1', 'services', 'collateral'),
                'NetworkPolicy': ('networking.k8s.io/v1', 'networkpolicies', 'collateral')}
    need(kind in versions and m.get('namespace') == NAMESPACE, 'foreign collateral resource')
    version, plural, name = versions[kind]
    need(item['apiVersion'] == version and m['name'] == name and m['labels'].get(COMPONENT) == 'collateral', 'wrong collateral resource')
    return ('/api/v1' if version == 'v1' else '/apis/'+version)+'/namespaces/'+NAMESPACE+'/'+plural+'/'+name


def render(run, node, image, expires):
    labels = {OWNER: run, COMPONENT: 'collateral'}
    meta = {'namespace': NAMESPACE, 'name': 'collateral', 'labels': labels,
            'annotations': {'cds.confidential.ai/cleanup-deadline': expires}}
    namespace = {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': NAMESPACE, 'labels': labels,
        'annotations': {'ovn.kubernetes.io/logical_switch': 'cloud-infra', 'cds.confidential.ai/cleanup-deadline': expires}}}
    policy = {'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy', 'metadata': copy.deepcopy(meta),
        'spec': {'podSelector': selector(run, 'collateral'), 'policyTypes': ['Ingress', 'Egress'],
            'ingress': [{'from': [{'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': NS}},
                                  'podSelector': selector(run, 'cds')}], 'ports': [{'protocol': 'TCP', 'port': 3128}]}],
            'egress': [dns_rule(), {'to': [{'ipBlock': {'cidr': '0.0.0.0/0', 'except': PUBLIC_EXCEPT}}],
                                   'ports': [{'protocol': 'TCP', 'port': 443}]}]}}
    service = {'apiVersion': 'v1', 'kind': 'Service', 'metadata': copy.deepcopy(meta),
        'spec': {'selector': labels, 'ports': [{'name': 'collateral', 'port': 3128, 'targetPort': 3128}]}}
    proxy = pod(run, '-proxy', 'collateral', 0, node, image,
        ['sh', '-ec', 'while [ ! -x /tools/proxy ]; do sleep 1; done; exec /tools/proxy'], expires,
        [{'name': 'tools', 'mountPath': '/tools'}], [{'name': 'tools', 'emptyDir': {'sizeLimit': '32Mi'}}])
    proxy['metadata']['namespace'] = NAMESPACE
    proxy['spec']['restartPolicy'] = 'Never'
    proxy['spec']['activeDeadlineSeconds'] = 4500
    proxy['spec']['containers'][0]['resources'] = {'requests': {'cpu': '25m', 'memory': '32Mi'},
                                                  'limits': {'cpu': '200m', 'memory': '128Mi'}}
    proxy['spec']['containers'][0]['readinessProbe'] = {'httpGet': {'path': '/healthz', 'port': 3128}, 'periodSeconds': 2}
    return [namespace, policy, service, proxy]
