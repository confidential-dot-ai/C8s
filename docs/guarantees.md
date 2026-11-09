# Guarantees

What a C8s deployment promises: for each promise, what it covers, what enforces
it, and how to check it. The parts and their layout are in
[overview.md](overview.md), the terms in [glossary.md](glossary.md), and the
promises adversary by adversary in [security-model.md](security-model.md). What
enforces a promise can differ by CVM mode, the node shape
([overview.md](overview.md#cvm-modes-and-hardware-platforms)); where it does,
the section says so.

## Data stays in the TEE

A tenant's weights, prompts, responses, and secrets are in the memory of a
confidential VM — one whose memory the CPU encrypts and whose launch state the
hardware measures — and nowhere the host can read them in the clear.

It covers what C8s itself holds: the secret store and the mesh CA of CDS — the
Certificate Distribution Service, the VM outside the cluster holding C8s policy
and signing pod certificates — plus each pod's private key and volume plaintext,
none of them a Kubernetes object. A volume's ciphertext does sit on host
storage, so a key that leaks opens every copy of it the host kept, and a
`--mutable` volume carries no integrity tree.

- **Secret store**: values CDS holds in its own memory and releases only to a
  pod whose containers match a granting entry — [secrets.md](secrets.md).
- **Encrypted volumes**: host-stored dm-crypt images opened inside the CVM for
  a pod the allowlist names — [volumes.md](volumes.md).
- **Keys made where they are used**: pod keys and the mesh CA are generated in
  TEE memory and never written out.

A node is one trust domain: its pods share its TEE, so distrusting tenants
belong on separate nodes; availability, side channels, and physical attacks are
out of scope ([verify.md](verify.md) checks which image a node booted).

## Only allowlisted code runs

A container starts on a C8s node only if an allowlist entry — one the node
holds in its own boot config, or one an operator wrote under a signed write
token — names its image digest, and it starts with the command line,
environment, and mounts that entry pins.

The host chooses the image reference a pod presents, so no decision reads it:
every check keys on the digest. How much else an entry pins is the operator's
choice: `c8s allowlist add` writes `policy: any` for the command line,
environment, and mounts, and pinning each of them is a deliberate edit
([allowlist-entries.md](allowlist-entries.md)). Enforcement sits in the node
CVM, below the API server, and an applied policy also stops running containers
it no longer admits. On `gke` and `aks` the entries a node holds itself are
chart values a cluster administrator can also write, the node host-privilege
policy is off, and only the chart's `<release>-deny-host-namespaces` cluster
policy keeps host namespaces away from tenant pods
([overview.md](overview.md#cvm-modes-and-hardware-platforms)).

- **Admission plugin** (`nri-image-policy`): checks every container at
  creation, adjustment validation, and start, and the runtime starts no
  container while it is disconnected: on the measured node image from boot, on
  `aks` from boot once an install has staged the node, and on `gke` once the
  installer has run on that boot.
- **Base allowlist**: the entries the plugin holds in its own boot config, so a
  node admits the platform before CDS is reachable.
- **Host privilege**: the measured node image refuses host namespaces, binds,
  devices, hooks, sysctls, and capabilities beyond its default set outside its
  own measured components.

All three are [allowlist-and-capabilities.md](allowlist-and-capabilities.md).
Two openings are the operator's: a `gke` or `aks` install admits `kube-system`
by the digests the images running there carried when it read the cluster, and
`nriImagePolicy.policy.mode: audit` logs a denial instead of enforcing it.

On a `gke` or `aks` node, a pod whose sandbox the runtime created before the
plugin registered gets no identity, certificate or secret, even for its later
containers. The plugin deletes such a pod; a controller that owns one replaces
it with a pod this node admits. That delete goes as the node, under the
credential the kubelet's kubeconfig names — on `gke` a credential helper the
plugin runs. A helper that fails leaves the pod named in the plugin's log for an
operator to delete; a helper that never returns holds that node's deletes with
no such line. A denied image may run until the plugin is
ready and stops it. That window opens on a fresh node, for as long as the
plugin is down on a running node, and on every `gke` reboot: a `gke` node
rebuilds its containerd configuration in tmpfs `/etc` at boot, so until the
installer has run on that boot nothing launches the plugin and nothing
requires it. An `aks` node keeps that configuration, so after a boot
containerd starts no container until the plugin registers, while a sandbox
created before it registered still loses its identity. The host chooses when a
node boots and how soon the installer runs. An install on a provider's stock
node image is for test and evaluation: the files that name the plugin and its
policy are the host's, under no measurement. Production runs the measured node
image — on bare metal, or as a custom VM image on GKE — which has no boot
window: its CNI needs the plugin before any pod sandbox gets a network.

## Identity comes from hardware evidence

A C8s component proves what it is with a hardware-signed report over a key it
generated inside the TEE, not with a name an administrator assigned to it.

A report carries the guest's launch measurement — on TDX the firmware's, with
the guest in the runtime registers ([measurements.md](measurements.md)) — so
identity is earned per boot. A challenge makes the report of one issuance
fresh; the report embedded in a certificate binds that certificate's key
instead. On the evidence path a verifier re-checks the peer's report against its
own pins on every connection; on the chain path it admits a mesh CA signature
alone, proving measurement at issuance, not at handshake. On `aks` the report
comes from the Azure vTPM
([overview.md](overview.md#cvm-modes-and-hardware-platforms)).

- **armTLS**: mutual TLS whose certificates carry evidence in an X.509
  extension; the CDS routes a pod uses before it has a certificate are
  server-authenticated only — [armtls.md](armtls.md).
- **Sandbox identity**: a token the node's admission inventory — which records
  the containers each pod sandbox ran — signs over a pod's key and CDS's
  challenge, stamped on the pod's certificate with the matched workload when the
  pod matches one entry — [armtls.md](armtls.md#sandbox-identity).
- **Launch binding**: on `bare-metal`, the digest of the document a worker
  boots with, bound into its evidence —
  [launch-configuration.md](launch-configuration.md).

A name on a self-issued certificate is peer-chosen, so `c8s verify` needs
`--mesh-ca` to read one; the OIDs are
[certificate-extensions.md](certificate-extensions.md).

## No privileged way in

On a measured node image no interface starts a new process in a running
container or hands one host privilege, for any principal.

Two independent layers close it: the kubelet serves no `exec`, `attach` or
`port-forward`, and the measured `c8s-runc` wrapper denies the `exec` verb
under the runtime, where a CRI call, an exec probe, or a lifecycle hook lands
([node-exec-mode.md](node-exec-mode.md)). `gke` and `aks` keep the ordinary
exec path ([overview.md](overview.md#cvm-modes-and-hardware-platforms)).

- **Privilege floor**: the capability, `no_new_privs`, namespace, and
  privileged-mark limits `c8s-runc` enforces on every container of a member pod
  outside the node's own exempt namespaces; the pod sandbox keeps the
  privileges the runtime gave it —
  [node-exec-mode.md](node-exec-mode.md#the-privilege-floor).
- **Platform role**: the identity a measured base grants one C8s node-side
  invocation, with the command line and mounts its measured declaration pins —
  [allowlist-and-capabilities.md](allowlist-and-capabilities.md#host-privilege).

Creating a pod is not what this closes: whoever can create one chooses its
initial process, which the allowlist restricts.

## Routes are what the operator signed

The router forwards a public request only to the backend an operator-signed
route manifest names for it, and tells a client which manifest it is serving.

The router is the front door for application traffic. It answers 503 until a
manifest is applied, refuses one whose write token does not verify, and binds
the digest of the manifest it applied into the attested handshakes its front
door offers, so a session routes by the two digests that handshake bound — the
manifest's and the router's own allowlist digest — and nothing else.
CDS's own API is reachable separately, at the address the install named with
`--cds-address`.

- **Route manifest**: the operator-signed hosts, paths, and backends CDS
  stores — [operator.md](operator.md#route-manifest).
- **Workload backends**: a backend must present a certificate stamped with the
  name the manifest asks for, and with the allowlist digest on the router's own
  certificate while that carries a stamp — the name alone while it does not —
  so a redefined entry does not inherit the route —
  [routes-evidence.md](routes-evidence.md).
- **Session binding**: once the manifest or the router's own stamp changes, the
  session's requests get 503 and the client attests again —
  [routes-evidence.md](routes-evidence.md#session-binding).

A baked node takes the operator keys from the CDS configuration its document
pins ([launch-configuration.md](launch-configuration.md)); elsewhere they are
Kubernetes configuration, so a client that cares pins the route digest or the
keys — `c8s verify --route-digest`, `--operator-keys` ([verify.md](verify.md)).

## Anyone can verify it

A relying party outside the cluster can check, on the connection it is about to
use, that it is talking to a genuine TEE running code it pinned.

`c8s verify` fetches evidence from the router, CDS, or a workload pod — or
reads evidence you saved earlier — checks it against the AMD or Intel signature
chain and the pins you pass, and prints what it proved and what it did not.
Measurement covers boot state, so a verdict is about the code that booted, not
the state the node reached since — except where a TDX node measures the
allowlist policies it applies ([measurements.md](measurements.md)).

- **Measurement pin**: the launch measurement, or the whole guest image, a
  verifier requires, and the measurements config `c8s measurements` derives
  from a published node image build — [measurements.md](measurements.md).
- **Mesh CA**: the anchor that turns a stamped sandbox ID, workload name, or
  allowlist digest into a claim a verifier can hold —
  [armtls.md](armtls.md#cds-issuance).
- **Certificate extensions**: every OID a C8s certificate carries, what it
  holds, and who checks it —
  [certificate-extensions.md](certificate-extensions.md).

A verdict covers one connection to one replica at one instant, so every client
verifies its own, and without `--measurements` it says only that the endpoint
is some TEE ([verify.md](verify.md), [releases.md](releases.md)).

## Design intentions

Guarantees rest on hardware evidence, not on cluster configuration the
adversary can edit. A workload is its image digests plus the command line,
environment, and mounts an entry pins, not a Kubernetes principal. Operators
choose their own pins, and what measurement does not cover is for the relying
party to check.
