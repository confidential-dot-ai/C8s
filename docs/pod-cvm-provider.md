# Schedule Kubernetes Pods into Cloud CVMs

The optional Pod CVM provider lets the Kubernetes scheduler place an opted-in
Pod on a virtual node. The operator then launches one Cloud CVM for that Pod
UID, supplies its signed workload at boot, and projects verified guest status
back to Kubernetes. Deleting the Pod terminates its CVM before releasing the
provider finalizer.

This is a cold-launch provider. It does not require a pool of generic guests or
an assignment service. Each new Pod UID gets a new VM; a rebooted or terminal VM
is never reused for that UID. Kubernetes workload controllers can create a
replacement Pod in their normal way.

## Platform configuration

Use a validated TDX Pod image, its exact published `manifest.json`, and a Cloud
catalog version pointing to that image. The current Pod measurement contract
does not support SNP. The CDS server must authorize this image and the provider's
Pod launch public key through its separate Pod image policy; see
[the Pod launch contract](operator.md#authenticated-launch-configuration).
Use a Pod signing key distinct from the CDS/server and agent launch keys.

The operator loads trusted configuration once at startup. Put `config.json` and
the referenced files in a Secret in the operator's release namespace. Relative
paths resolve beside `config.json`. For example, replace the catalog, location
and size placeholders with compatible Cloud values:

```json
{
  "providerID": "cloud-pods",
  "nodeName": "cloud-pods",
  "namespace": "c8s-system",
  "cloudURL": "https://api.cloud.confidential.ai",
  "cloudTokenFile": "cloud-token",
  "image": "c8s-pod@CATALOG_VERSION",
  "imageManifestFile": "manifest.json",
  "launchKeyFile": "pod.key",
  "serverAddress": "198.51.100.10",
  "serverPublicKeyFile": "server.pub",
  "workloadsFile": "workloads.json",
  "clusterID": "demo",
  "size": "CLOUD_SIZE",
  "location": "CLOUD_LOCATION",
  "vCPUs": 4,
  "memoryMiB": 8192,
  "reservedMemoryMiB": 1024,
  "maxPods": 10,
  "verificationTimeoutSeconds": 600,
  "publicIP": "shared",
  "meshPeers": []
}
```

`vCPUs` and `memoryMiB` describe one VM of the selected size. Each workload must
fit that VM after the memory reserve. The virtual node advertises the aggregate
capacity for `maxPods`; this is a placement limit, not a reservation of Cloud
capacity. The provider checks the returned VM's capacity before accepting it.
The default reserve is 1024 MiB and the default public IP mode is `shared`.

```sh
kubectl -n c8s-system create secret generic pod-cvm-provider \
  --from-file=config.json=provider/config.json \
  --from-file=cloud-token=provider/cloud-token \
  --from-file=manifest.json=provider/manifest.json \
  --from-file=pod.key=provider/pod.key \
  --from-file=server.pub=provider/server.pub \
  --from-file=workloads.json=provider/workloads.json
```

Enable the provider in the existing chart release:

```yaml
operator:
  podCVMProvider:
    enabled: true
    existingSecret: pod-cvm-provider
```

The chart mounts this Secret read-only at `/mnt/c8s-data/pod-cvm`, readable by
the operator's group, and passes
`--pod-cvm-provider-config=/mnt/c8s-data/pod-cvm/config.json`. Direct operator
invocations can use the same flag. Leader election and Pod admission webhooks
must remain enabled. The configuration namespace must match
`--leader-election-namespace`.

Keep this namespace restricted to platform administrators. It contains the
launch signing key, Cloud credential and durable provider records. The chart
grants Secret access only in the release namespace. The provider additionally
needs cluster access to Pods/status and Nodes/status; its node lease lives in
`kube-node-lease`.

The chart's host DaemonSets and cleanup hooks exclude nodes labelled
`confidential.ai/pod-cvm=true` through required node affinity. Apply the same
exclusion to third-party infrastructure DaemonSets with wildcard tolerations,
such as networking or monitoring agents. A wildcard toleration accepts the
virtual node's `NoSchedule` taint; these agents require a real host node.
For a DaemonSet without existing required node affinity, add:

```yaml
spec:
  template:
    spec:
      affinity:
        nodeAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            nodeSelectorTerms:
              - matchExpressions:
                  - key: confidential.ai/pod-cvm
                    operator: NotIn
                    values: ["true"]
```

When required affinity already exists, append this expression to **every
nonempty** `nodeSelectorTerms` entry. Terms are OR alternatives; adding a separate
term would allow an existing alternative to select the virtual node. Leave
explicit empty required selectors and empty terms unchanged: they match no
nodes. Keep existing expressions, match fields, node selectors, and preferred
affinity.

## Workload opt-in

Create the Pod in a namespace covered by the admission webhooks. Set
`metadata.annotations["confidential.ai/pod-cvm"]` to `"true"` and explicitly set
`spec.automountServiceAccountToken: false` in the submitted object. Kubernetes
service-account admission runs before these webhooks, so disabling token
automount later cannot remove an already-injected projected volume.

For a Deployment or Job, put the annotation and token setting on its Pod
template. The webhook adds the virtual-node selector and exact `NoSchedule`
toleration; leave `spec.nodeName` unset so the normal scheduler chooses the node.
It bypasses host get-cert/mesh injection because the guest supplies its measured
mesh endpoint.

The workload must satisfy the [guest Pod contract](operator.md#authenticated-launch-configuration):
digest-pinned images, memory `emptyDir` volumes, bounded privileges and supported
HTTP probes. The provider also rejects cluster-dependent Secret/ConfigMap
environment references, `envFrom`, image pull Secrets, nondefault service
accounts, resource claims, RuntimeClasses and custom readiness gates. Use
per-container resource requests and limits. Whole-map annotation FieldRefs and
provider/kubelet annotation FieldRefs are unsupported.

Supported metadata FieldRefs snapshot the external Pod's name, namespace, UID
and keyed labels/annotations into its signed launch. Node and IP FieldRefs
resolve inside the guest.

Execution mode is fixed at Pod creation. After scheduling, workload fields and
Downward API metadata used by the workload are immutable. Unrelated metadata,
status and finalizer updates remain available, including when new provider
admission is disabled. Replace a Pod to change its workload.

## Status and connectivity

Cloud's `running` state does not make a Pod ready. The provider fetches fresh,
attested guest status, verifies its Pod identity and maps the application's
container states back to the original Pod. It preserves the scheduler's
`PodScheduled` condition and hides the guest-injected mesh endpoint. Failed
verification withdraws readiness and advertised endpoints.

`verificationTimeoutSeconds` defaults to 600 (10 minutes), with a permitted range
of 30 to 86400 seconds. The initial window begins when the provider persists the
Pod's launch intent, including Cloud provisioning and boot. A fresh, verified
status projection matching the assigned Pod clears the window. Later loss of
verification begins another window of the same frozen duration. A valid attested
`Pending` Pod or a running Pod whose application is unready does not time out on
this basis.

At expiry, the provider persists `Failed` with reason `GuestVerificationTimedOut`,
withdraws readiness and endpoints, and requests termination of that Pod's VM.
A late successful response cannot revive the Pod; replacement requires a new
Pod UID. Cloud termination is retried independently of status publication and
retains the cleanup record until Cloud confirms termination.

The timeout and active deadline are saved with the launch intent. Provider
restarts and configuration changes do not extend an existing window. Records
created before timeout support receive one persisted grace window on upgrade.
Deadlines use the provider's trusted wall clock, not guest-reported time; keep
the provider hosts' clocks synchronized. Provider downtime consumes the window:
an expired record fails when reconciliation resumes. Status publication requires
an available Kubernetes API, and termination may take longer during a Cloud
outage. Waiting retries are scheduled within 10 seconds, shortened to the
remaining budget; individual Cloud and guest calls are capped by that budget.

Application ingress comes from declared TCP `containerPort` values. The provider
also exposes the guest status port, 8443. Neither is a host readiness port:
application HTTP probes run inside the guest through its mesh endpoint. Cloud
readiness ports are left empty.

With shared public IPv4, Cloud translates ports. The provider records the
application's explicit `{name, host, port}` endpoints in the
`confidential.ai/pod-cvm-endpoints` annotation and leaves `status.podIP` empty.
Ordinary Kubernetes Service/EndpointSlice routing therefore cannot use those
shared endpoints. With `publicIP: "dedicated"`, a Pod IP is published only after
all declared endpoints preserve their original ports on one address.

Signed `meshPeers` enable authenticated TCP connections to known peer tuples.
Other IPv4 TCP/UDP traffic uses the guest's internet egress and upstream DNS.
This provider does not discover peers dynamically, select a Cloud private network
or provide Kubernetes cluster DNS/Service networking inside the guest.

## Recovery and teardown

Before Cloud creation, the operator saves the exact signed request in a
provider-owned Secret and adds a Pod finalizer. Retries use the same request and
idempotency key, including after restart or an ambiguous create response. The
record is retained until deletion is confirmed. An orphan sweep also handles
force-deleted Pods and same-name Pods with a new UID. Do not manually remove
provider records or finalizers to bypass cleanup.

An unresolved create intent older than 24 hours is retained for explicit Cloud
reconciliation, including its cleanup finalizer. The provider does not blindly
replay such an old uncertain request.

Existing records retain their original launch inputs when configuration changes.
They also bind the Cloud origin and credential hash. Drain all records with the
original credential before rotating that credential, changing accounts or
renaming the provider/node. An expired or replaced token cannot silently adopt
old records; restore the original valid credential or arrange an explicit
record migration before removing it.

Delete managed Pods and wait for their CVMs and records to disappear before
disabling or uninstalling the provider. Disabling new admission alone does not
remove existing Cloud resources. Cloud outages stop virtual-node heartbeats;
Kubernetes applies its normal node health timeout. The shared admission webhook
continues serving ordinary Pods during such an outage.
