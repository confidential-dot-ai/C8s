# Deploy the sample workload

Run the sample confidential workload on a cluster that already has C8s, and see
what the admission webhook injected into the pod.

## Prerequisites

- C8s installed ([QUICKSTART.md](QUICKSTART.md)) and its operator key.
- `crane` on PATH: the sample sets no `command`, so the entry takes that image's
  baked argv from the registry.

## 1. Admit the sample image

Nodes admit containers by image digest and deny everything else, so the sample
needs a workload entry: an allowlist entry naming the containers a pod may run.
Open a path to CDS and set `$PIN` and `$KEY` as the first step of
[workloads.md](workloads.md) shows, then write it. `--env any` admits any
environment, `--mounts deny` platform mounts alone, and `apply` lints and diffs
before signing:

```sh
kubectl create -o json --dry-run=server -f samples/nginx-confidential-pod.yaml |
  c8s allowlist derive demo-nginx - --env any --mounts deny |
  c8s allowlist apply - $PIN $KEY
```

## 2. Create a Restricted namespace

The node image enforces the Restricted PodSecurity standard in every tenant
namespace, and a confidential workload needs no exemption: no pod volume carries
host state. The sidecars' read-only mount onto the node's admission inventory —
the service that records a pod's containers and signs tokens about them — is
made by the node below the pod spec, not by a `hostPath` in it.

```sh
kubectl create namespace demo
kubectl label namespace demo pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=latest \
  pod-security.kubernetes.io/warn=restricted pod-security.kubernetes.io/audit=restricted
```

`kubectl get namespace demo --show-labels` confirms the four labels.

## 3. Deploy the sample

```sh
kubectl -n demo apply -f samples/nginx-confidential-pod.yaml
kubectl -n demo rollout status deploy/demo-nginx
```

`rollout status` is the confirmation: it returns once the pod is ready. A
rollout that does not progress usually means no entry matches the containers the
pod runs, which only CDS can tell you — see the confirm step of
[workloads.md](workloads.md).

Injection covers every pod of a namespace the webhook is configured for; the
pod template's `confidential.ai/cw: demo-nginx` annotation adds the workload the
pod belongs to, and requests `c8s-demo-nginx.demo.svc` on its certificate.

## 4. See what was injected

```sh
kubectl -n demo get pod -l app=demo-nginx -o \
  jsonpath='{.items[0].spec.initContainers[*].name}{"\n"}{.items[0].spec.containers[*].name}{"\n"}'
```

```text
c8s-mesh c8s-cert c8s-cert-wait
nginx
```

`c8s-mesh`, the pod's mesh endpoint, carries its traffic, and `c8s-cert` obtains
and renews its certificate; both keep running. `c8s-cert-wait` runs once and
holds `nginx` until the first certificate exists, so the workload never starts
unattested. The certificate lands in `c8s-certs`, a memory-backed volume mounted
at `/etc/c8s/certs` into the injected containers alone
([getcert-workload-binding.md](getcert-workload-binding.md)).

## Reset

```sh
kubectl delete namespace demo
c8s uninstall --namespace c8s-system
```

`c8s uninstall` removes the release, then sweeps the node-side artifacts it
left: the admission plugin's containerd registration, the mesh's netfilter
chains.
