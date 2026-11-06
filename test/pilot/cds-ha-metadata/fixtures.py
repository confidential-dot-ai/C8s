"""Render a disposable three-worker metadata service; never apply or publish it."""
import base64
import copy
import re

NS = "p-internal"
OWNER = "cloud.confidential.ai/cds-ha-owner"
COMPONENT = "cloud.confidential.ai/cds-ha-component"
SLOT = "cloud.confidential.ai/cds-ha-slot"


def need(ok, message):
    if not ok:
        raise ValueError(message)


def validate(run, nodes, image):
    need(re.fullmatch(r"cds-ha-[0-9a-f]{12}", run), "invalid owned run")
    need(len(nodes) == 3 and len({n['name'] for n in nodes}) == 3 and
         len({n['uid'] for n in nodes}) == 3, "three distinct observed workers required")
    for node in nodes:
        need(re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,62}", node['name']) and
             re.fullmatch(r"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}", node['uid']), "invalid worker identity")
    need(re.fullmatch(r"[^@\s]+@sha256:[0-9a-f]{64}", image), "digest-pinned population image required")


def meta(run, suffix, component, slot=None, expires=None):
    labels = {OWNER: run, COMPONENT: component}
    if slot is not None:
        labels[SLOT] = str(slot)
    out = {"name": run + suffix, "namespace": NS, "labels": labels}
    if expires:
        out['annotations'] = {'cds.confidential.ai/cleanup-deadline': expires}
    return out


def selector(run, component=None, slot=None):
    labels = {OWNER: run}
    if component:
        labels[COMPONENT] = component
    if slot is not None:
        labels[SLOT] = str(slot)
    return {"matchLabels": labels}


def dns_rule():
    return {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}},
                    "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}}}],
            "ports": [{"protocol": p, "port": 53} for p in ("TCP", "UDP")]}


def security():
    return {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
            "capabilities": {"drop": ["ALL"]}}


def pod(run, suffix, component, slot, node, image, command, expires, mounts, volumes):
    return {"apiVersion": "v1", "kind": "Pod", "metadata": meta(run, suffix, component, slot, expires),
        "spec": {"automountServiceAccountToken": False, "enableServiceLinks": False,
            "restartPolicy": "Always", "activeDeadlineSeconds": 3600, "terminationGracePeriodSeconds": 10,
            "nodeSelector": {"kubernetes.io/hostname": node['name'],
                "cloud.confidential.ai.node-restriction.kubernetes.io/node-uid": node['uid']},
            "securityContext": {"runAsNonRoot": True, "runAsUser": 107, "runAsGroup": 107, "fsGroup": 107,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{"name": component, "image": image, "command": command,
                "securityContext": security(), "resources": {"requests": {"cpu": "100m", "memory": "128Mi"},
                    "limits": {"cpu": "1", "memory": "512Mi"}}, "volumeMounts": mounts}], "volumes": volumes}}


def secret(run, suffix, component, slot, values, expires):
    return {"apiVersion": "v1", "kind": "Secret", "metadata": meta(run, suffix, component, slot, expires),
            "type": "Opaque", "immutable": True,
            "data": {k: base64.b64encode(v if isinstance(v, bytes) else v.encode()).decode() for k, v in values.items()}}


def private_material(p, name):
    p['spec']['volumes'] += [{"name": "source", "secret": {"secretName": name, "defaultMode": 0o440}},
                            {"name": "private", "emptyDir": {"medium": "Memory", "sizeLimit": "1Mi"}}]
    p['spec']['initContainers'] = [{"name": "private-files", "image": p['spec']['containers'][0]['image'],
        "command": ["sh", "-ec", "umask 077; cp /source/* /private/; chmod 600 /private/*"],
        "securityContext": security(), "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
            "limits": {"cpu": "100m", "memory": "64Mi"}},
        "volumeMounts": [{"name": "source", "mountPath": "/source", "readOnly": True},
                         {"name": "private", "mountPath": "/private"}]}]
    p['spec']['containers'][0]['volumeMounts'].append({"name": "private", "mountPath": "/private", "readOnly": True})


def render(run, nodes, image, certificates, expires, cluster_id=None, token=None):
    validate(run, nodes, image)
    ports = [{"protocol": "TCP", "port": p} for p in (2379, 2380, 9443)]
    pods = {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": NS}}, "podSelector": selector(run)}
    admin = {"apiVersion": "policy.networking.k8s.io/v1alpha1", "kind": "AdminNetworkPolicy",
        "metadata": {"name": run, "labels": {OWNER: run}, "annotations": {'cds.confidential.ai/cleanup-deadline': expires}},
        "spec": {"priority": 89, "subject": {"pods": pods}, "egress": [{"name": "owned-metadata-only",
            "action": "Pass", "to": [{"pods": pods}], "ports": [{"portNumber": p} for p in ports]}]}}
    items = [] if cluster_id else [admin]
    initial = ','.join(f"m{i}=https://{run}-e{i}.{NS}.svc.cluster.local:2380" for i in range(3))
    endpoints = ','.join(f"https://{run}-e{i}.{NS}.svc.cluster.local:2379" for i in range(3))
    for i, node in enumerate(nodes):
        data = {"name": "data", "persistentVolumeClaim": {"claimName": f"{run}-data{i}"}}
        if not cluster_id:
            claim = {"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": meta(run, f"-data{i}", "data", i, expires),
                "spec": {"accessModes": ["ReadWriteOnce"], "storageClassName": "local-path",
                         "resources": {"requests": {"storage": "1Gi"}}}}
            claim['metadata']['annotations']['volume.kubernetes.io/selected-node'] = node['name']
            items.append(claim)
            population = pod(run, f"-pop{i}", "population", i, node, image, ["sleep", "1800"], expires,
                [{"name": "data", "mountPath": "/data"}], [data])
            population['spec']['restartPolicy'] = 'Never'
            population['spec']['activeDeadlineSeconds'] = 1800
            items.append(population)
            values = {'ca.pem': certificates['etcd_ca'], **certificates['members'][i]}
            items.append(secret(run, f"-e{i}", "etcd", i, values, expires))
            url = f"https://{run}-e{i}.{NS}.svc.cluster.local"
            args = ["/data/bin/etcd", "--name", f"m{i}", "--data-dir", "/data/db",
                "--listen-client-urls", "https://0.0.0.0:2379", "--advertise-client-urls", url+':2379',
                "--listen-peer-urls", "https://0.0.0.0:2380", "--initial-advertise-peer-urls", url+':2380',
                "--initial-cluster", initial, "--initial-cluster-token", run, "--initial-cluster-state=new",
                "--client-cert-auth=true", "--trusted-ca-file=/private/ca.pem", "--cert-file=/private/tls.crt", "--key-file=/private/tls.key",
                "--peer-client-cert-auth=true", "--peer-trusted-ca-file=/private/ca.pem", "--peer-cert-file=/private/tls.crt", "--peer-key-file=/private/tls.key",
                "--quota-backend-bytes=67108864", "--max-request-bytes=2097152", "--log-level=warn"]
            p = pod(run, f"-e{i}", "etcd", i, node, image, args, expires, [{"name": "data", "mountPath": "/data"}], [data])
            private_material(p, f"{run}-e{i}")
            service = {"apiVersion": "v1", "kind": "Service", "metadata": meta(run, f"-e{i}", "etcd", i, expires),
                "spec": {"clusterIP": "None", "publishNotReadyAddresses": True, "selector": selector(run, 'etcd', i)['matchLabels'],
                    "ports": [{"name": name, "port": port, "targetPort": port} for name, port in [('client', 2379), ('peer', 2380)]]}}
            # One policy per member makes a partition an update to only that
            # member's own ingress/egress rules, with no shared network change.
            policy = {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": meta(run, f"-e{i}", "etcd", i, expires),
                "spec": {"podSelector": selector(run, 'etcd', i), "policyTypes": ['Ingress', 'Egress'],
                    "ingress": [{'from': [{'podSelector': selector(run)}], 'ports': ports[:2]}],
                    "egress": [{'to': [{'podSelector': selector(run, 'etcd')}], 'ports': [ports[1]]}, dns_rule()]}}
            items += [service, policy, p]
        else:
            need(re.fullmatch(r"[1-9][0-9]{0,19}", cluster_id) and token and len(token) >= 32, "pinned cluster and scoped token required")
            values = {'ca.pem': certificates['etcd_ca'], 'client.crt': certificates['client']['tls.crt'],
                      'client.key': certificates['client']['tls.key'], 'token': token, **certificates['adapters'][i]}
            items.append(secret(run, f"-a{i}", "adapter", i, values, expires))
            args = ['/data/bin/metadata', '--listen=:9443', '--namespace='+run, '--token-file=/private/token',
                '--tls-cert=/private/tls.crt', '--tls-key=/private/tls.key', '--etcd-endpoints='+endpoints,
                '--etcd-cluster-id='+cluster_id, '--etcd-root-ca=/private/ca.pem',
                '--etcd-client-cert=/private/client.crt', '--etcd-client-key=/private/client.key']
            p = pod(run, f"-a{i}", "adapter", i, node, image, args, expires,
                [{'name': 'data', 'mountPath': '/data/bin', 'subPath': 'bin', 'readOnly': True}], [data])
            private_material(p, f"{run}-a{i}")
            p['spec']['containers'][0]['readinessProbe'] = {'tcpSocket': {'port': 9443}, 'periodSeconds': 2}
            policy = {'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy', 'metadata': meta(run, f"-a{i}", 'adapter', i, expires),
                'spec': {'podSelector': selector(run, 'adapter', i), 'policyTypes': ['Ingress', 'Egress'],
                    'ingress': [{'from': [{'podSelector': selector(run)}], 'ports': [ports[2]]}],
                    'egress': [{'to': [{'podSelector': selector(run, 'etcd')}], 'ports': [ports[0]]}, dns_rule()]}}
            items += [policy, p]
    if cluster_id:
        items.append({'apiVersion': 'v1', 'kind': 'Service', 'metadata': meta(run, '-api', 'adapter', expires=expires),
            'spec': {'selector': selector(run, 'adapter')['matchLabels'], 'ports': [{'name': 'tls', 'port': 9443, 'targetPort': 9443}]}})
    return items


def partition(policy):
    p = copy.deepcopy(policy)
    need(p['kind'] == 'NetworkPolicy' and p['metadata']['labels'].get(COMPONENT) == 'etcd', "only an owned member can be partitioned")
    need(p['spec']['podSelector'] == selector(p['metadata']['labels'][OWNER], 'etcd', int(p['metadata']['labels'][SLOT])), "member selector changed")
    p['spec']['ingress'] = []
    p['spec']['egress'] = [dns_rule()]
    return p
