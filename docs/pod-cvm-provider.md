# Schedule Kubernetes Pods into Cloud CVMs

The optional Pod CVM provider lets the Kubernetes scheduler place an opted-in
Pod on a virtual node. The operator then launches one Cloud CVM for that Pod
UID from a generic launch document that names no pod, verifies that the guest
has run no containers, delivers the pod through one authenticated assignment,
and projects verified guest status back to Kubernetes. Deleting the Pod
terminates its CVM before releasing the provider finalizer.

Every pod CVM boots generic and receives exactly one pod. An assigned, rebooted
or terminal VM is never reused for another Pod. Kubernetes workload controllers
can create replacement Pods in their normal way.

## Platform configuration

Use a validated TDX Pod image, its exact published `manifest.json`, and a Cloud
API/catalog launch contract that accept `c8s-launch/v2`. Historical v1 images and
catalog entries do not satisfy this requirement. The Pod measurement contract
does not support SNP; the separate measured CDS image may use another TEE.
CDS must authorize the Pod image and provider's Pod launch public key in its
measured Pod image policy; see [the Pod launch contract](operator.md#pod-cvm).
Use a Pod signing key that signs nothing else.

Before upgrading a provider that wrote records of an earlier shape, stop new
placements and drain its managed Pods using the original provider. Wait for all
old VMs, including uncertain allocations, to finish cleanup before replacing the
provider. This version reads only its own record version; it reports an older
record as `ProviderStateUnavailable`, holds its Pod, and does not rewrite the
record's signed bytes or silently migrate it. Retain the original provider until
every old obligation is resolved.

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
  "image": "c8s-pod@V2_COMPATIBLE_CATALOG_VERSION",
  "imageManifestFile": "manifest.json",
  "launchKeyFile": "pod.key",
  "cdsAddress": "cds.example.com:8443",
  "cdsImagePolicyFile": "cds.json",
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

`cdsAddress` names the external CDS host and port; `cdsImagePolicyFile` contains
the generated policy binding every admitted CDS image to the same exact measured
CDS configuration. Both are required. A DNS host and a different CDS image or
TEE are supported. Every generic launch
document carries this explicit CDS trust. Changing it affects new records only;
existing Pod records retain their signed bytes.

The provider takes no CDS pin decree: after a CDS image roll, deploy an updated
`cdsImagePolicyFile`. Existing frozen Pod and assignment records keep their
original trust.

`workloadsFile` holds the `c8s.allowlist/v1` entries the provider signs into
every assignment; its entries may be empty. `meshPeers` lists the static mesh
peer endpoints every assignment carries.

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
  --from-file=cds.json=provider/cds.json \
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

To change the configuration, replace the Secret (for example `kubectl create
secret ... --dry-run=client -o yaml | kubectl apply -f -`) and run
`kubectl -n c8s-system rollout restart deployment/c8s-operator`.

### Beside a workers' control plane

On a cluster of workers the operator runs beside the control plane, outside
any TEE, so the provider runs there too and the pod launch key stays with it.
Render the control plane's objects with the provider's grants, then pass the
same flag to the operator on its host:

```sh
c8s worker control-plane render --pod-cvm-provider ... --output-dir out
c8s operator --pod-cvm-provider-config /etc/c8s/pod-cvm/config.json ...
```

`--pod-cvm-provider` binds the provider's cluster grants and its Secret grant
in `c8s-system` to the user `c8s-operator`. The provider is untrusted for
confidentiality, like the control plane: a pod's attestation and the CDS
replay of its measured journal protect it, and the signed document and
assignment protect integrity and availability.

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

## Generic boot and assignment

On a Pod bound to the virtual node, the provider validates the Pod, freezes it
and writes one record for its UID: the signed generic launch document, the
allocation identity used as the Cloud idempotency key, the frozen Pod, the
allowlist entries and mesh peers, and the verification deadline. Only then does
it create the instance, with the guest status port and the Pod's declared
application ports open from the start. The record counts against `maxPods` from
the moment it is written until Cloud confirms the instance destroyed; a Pod
that would exceed the budget gets no record and reports `CapacityLimit` until
capacity is released.

Once the instance runs and reports its endpoints, the provider verifies fresh
guest evidence and an empty measured list, fetches an assignment nonce on that
verified connection, signs the assignment over the connection's serving key and
saves the exact assignment bytes and serving key in the record before POSTing
them. Readiness still comes only from verified Pod status; until the guest
reports the assigned Pod the status reason is `AssignmentPending`.

A lost assignment reply keeps the same VM and record. The provider replays the
saved bytes to the same serving key and recovers through matching attested
status. It never signs a second assignment for the record, and refuses a guest
that presents another serving key, holds another Pod, or reports the Pod
without a saved assignment (`UnexpectedAssignedGuest`). If recovery cannot
establish valid Pod status within the frozen verification window, the Pod fails
and the VM is terminated. Refusal to issue an assignment nonce, or refusal of an
assignment whose nonce the guest has since discarded, uses the same bounded
failure path; it does not reset the deadline.

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

The workload must satisfy the [guest Pod contract](operator.md#pod-cvm):
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

## Client document

A client can attach a document to a Pod CVM and then check, from the Pod's
certificate, that the Pod was assigned exactly that document. C8s never
parses the document. Keep it small and stable: for example, the client's
public key, a random agent ID of at least 128 bits, and the client's
signature over both. It must hold no secrets: the control plane can read it.

Set `metadata.annotations["confidential.ai/client-document"]` to the standard
base64 of the document, at most 16 KiB decoded. The webhook refuses an
annotation that does not decode or is too large, refuses any change to it
after creation, and refuses a FieldRef to it.

1. The provider removes the annotation from the frozen Pod and signs the
   document into the assignment as its own `clientDocument` member. The
   assignment signature (domain `c8s-pod-assign/v2`) covers its SHA-256, so
   a changed document fails the guest's signature check. A guest accepts one
   assignment per boot, so a second document is refused.
2. The guest binds the document read-only into every container of the Pod at
   `/run/c8s/client-document`.
3. The guest puts `H = SHA-256(document)` into its Pod claims as
   `client_document_digest`. The quote that authorizes each certificate
   binds the claims, so CDS issues nothing for claims with another digest.
4. CDS stamps H on the Pod's leaf as the client document digest extension
   ([certificate-extensions.md](certificate-extensions.md)).

A Pod without the annotation has an empty document: no file, no claim and no
extension.

The agent label of a Pod is the lowercase, unpadded base32 of the first 16
bytes of H (26 characters). `armtls.AgentLabel` computes it.

To check a Pod's certificate against a document:

```sh
c8s verify --kind workload --mesh-ca mesh-ca.pem \
  --client-document document.bin <POD_ENDPOINT>
```

The verdict prints the digest and the agent label, and fails unless the leaf
chains to the mesh CA and names the SHA-256 of `document.bin`.

A Pod CVM leaf carries no hardware evidence: CDS issued it after verifying
the Pod's attestation. So the verdict rests on the chain to the mesh CA, which
you pinned after verifying CDS, and on the stamps (`--workload`,
`--client-document`, `--sandbox-id`). Pins on hardware evidence, such as
`--measurements` or `--image-manifest`, fail against it.

## Status and connectivity

Cloud's `running` state does not make a Pod ready. The provider fetches fresh,
attested guest status, verifies its Pod identity and maps the application's
container states back to the original Pod. It preserves the scheduler's
`PodScheduled` condition and hides the guest-injected mesh endpoint. Failed
verification withdraws readiness and advertised endpoints.

`verificationTimeoutSeconds` defaults to 600 (10 minutes), with a permitted range
of 30 to 86400 seconds. The initial window begins when the provider persists the
Pod's launch intent, including Cloud provisioning and boot. While Cloud has no
room for the Pod CVM size, the Pod reports `InsufficientCapacity` and the
provider retries the create within this window. A fresh, verified
status projection matching the assigned Pod clears the window. A later failure
of the guest itself (refused attestation, a status naming another Pod, a reboot,
an ended or replaced instance) begins another window of the same frozen
duration. A Cloud API or node outage does not: the Pod keeps its last status
with readiness unknown until the outage ends. While Cloud throttles the
provider (HTTP 429), the Pod reports `RateLimited` and the provider waits as
Cloud's `Retry-After` asks (at most five minutes, or the 10-second poll when it
names none) plus a few seconds of jitter, never past this window. A request
Cloud refuses as such (another 4xx, such as `invalid_request`) reports
`CloudRejectedRequest`, and the provider log names Cloud's problem code; a
create refusal that proves no VM exists ends the Pod `Failed` at once, any
other refusal runs this window. A valid attested `Pending` Pod or
a running Pod whose application is unready does not time out on this basis.

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

Before each Cloud creation, the operator saves the exact signed request in a
provider-owned Secret and holds the Pod with a finalizer. Retries use the same
request and idempotency key, including after restart or an ambiguous create
response. The record is retained until deletion is confirmed. An orphan sweep also handles
force-deleted Pods and same-name Pods with a new UID. Do not manually remove
provider records or finalizers to bypass cleanup.

A create whose response was lost is resolved, however old, by replaying the
exact saved request under its idempotency key: Cloud returns the instance it
created, or creates the one the provider then destroys. A replay Cloud refuses
outright, for example for lack of capacity, shows that nothing exists under the
key, and the Pod is released without an instance. Cleanup therefore never waits
on an unresolved create.

Existing records retain their original launch inputs when configuration changes.
Records key on the provider ID and the Pod UID, not on the Cloud credential, so
the credential can be rotated while records exist; the new credential must reach
the same Cloud account and instances. Renaming the provider orphans its records:
drain them first.

Delete managed Pods and wait for their CVMs and records to disappear before
disabling or uninstalling the provider. Disabling new admission alone does not
remove existing Cloud resources. Cloud outages stop virtual-node heartbeats;
Kubernetes applies its normal node health timeout. The shared admission webhook
continues serving ordinary Pods during such an outage.
