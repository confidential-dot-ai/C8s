# Guarantees

What a C8s deployment promises: for each promise, what it covers, what enforces
it, and how to check it. The parts and their layout are in
[overview.md](overview.md), the terms in [glossary.md](glossary.md), and the
promises adversary by adversary in [security-model.md](security-model.md). What
enforces a promise can differ by CVM mode, the deployment shape
`c8s install --cvm-mode` picks; where it does, the section says so.

## Data stays in the TEE

A tenant's weights, prompts, responses, and secrets are in the memory of a
confidential VM — one whose memory the CPU encrypts and whose launch state the
hardware measures — and nowhere the host can read them in the clear.

It covers what C8s itself holds: the secret store and the mesh CA of CDS — the
Certificate Distribution Service, the one in-cluster pod holding C8s policy and
signing pod certificates — plus each pod's private key and volume plaintext,
none of them a Kubernetes object. A volume's ciphertext does sit on host
storage, so a key that leaks opens every copy of it the host kept, and a
`--mutable` volume carries no integrity tree.

- **Secret store**: values CDS holds in its own memory and releases only to a
  pod whose containers match a granting entry — [secrets.md](secrets.md).
- **Encrypted volumes**: host-stored dm-crypt images opened inside the CVM for
  a pod the allowlist names — [volumes.md](volumes.md).
- **Keys made where they are used**: pod keys and the mesh CA are generated in
  TEE memory and never written out; public TLS mode `webpki` is the exception,
  its serving private key coming from an operator Secret the host can read.

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
  creation, adjustment validation, and start, and the runtime starts nothing
  while it is disconnected.
- **Base allowlist**: the entries the plugin holds in its own boot config, so a
  node admits the platform before CDS is reachable.
- **Host privilege**: the measured node image refuses host namespaces, binds,
  devices, hooks, and sysctls outside its own measured components.

All three are [allowlist-and-capabilities.md](allowlist-and-capabilities.md).
Two openings are the operator's: a `gke` or `aks` install admits `kube-system`
by the digests those pods ran at the plugin's first connect, and
`nriImagePolicy.policy.mode: audit` logs a denial instead of enforcing it.

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
- **Launch key binding**: on `bare-metal`, the public half of the operator
  keypair a node boots with, bound into its evidence —
  [launch-configuration.md](launch-configuration.md).

A name on a self-issued certificate is peer-chosen, so `c8s verify` needs
`--mesh-ca` to read one; the OIDs are
[certificate-extensions.md](certificate-extensions.md).

## No privileged way in

On a measured node image no interface starts a new process in a running
container or hands one host privilege — for any principal, including the holder
of the operator credential C8s releases.

Two independent layers close it: the API server denies `pods/exec`,
`pods/attach`, `pods/portforward`, and `pods/ephemeralcontainers`, and the
measured `c8s-runc` wrapper denies the `exec` verb under the runtime, where a
CRI call, an exec probe, or a lifecycle hook lands. The release node image
carries both; a development build (`C8S_DEV=1`) carries neither and has its own
measurement, so exec posture is what a verifier pins. `gke` and `aks` keep the
ordinary exec path
([overview.md](overview.md#cvm-modes-and-hardware-platforms)).

- **Privilege floor**: the capabilities, `no_new_privs`, namespace, and
  privileged-mark limits `c8s-runc` enforces on every container of a member pod
  outside the node's own exempt namespaces; the pod sandbox keeps the
  privileges the runtime gave it —
  [node-exec-mode.md](node-exec-mode.md#the-privilege-floor).
- **Platform role**: the identity a measured base grants one C8s node-side
  invocation, with the command line and mounts its measured declaration pins —
  [allowlist-and-capabilities.md](allowlist-and-capabilities.md#host-privilege).
- **Bounded operator credential**: an enumerated ClusterRole with no path to
  those guards ([operator.md](operator.md#bounded-operator)).

Creating a pod is not what this closes: whoever can create one chooses its
initial process, which the allowlist restricts.

## Routes are what the operator signed

The router forwards a public request only to the backend an operator-signed
route manifest names for it, and tells a client which manifest it is serving.

The router is the front door for application traffic. It answers 503 until a
manifest is applied, refuses one whose write token does not verify, and binds
the digest of the manifest it applied into the attested handshakes a TEE-held
front door offers (`cds`, `acme`; a `webpki` one offers attest-pq alone), so a
session routes by the two digests that handshake bound — the manifest's and the
router's own allowlist digest — and nothing else.
CDS's own API is reachable separately, by default on node port `30808`.

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

A baked node takes the operator keys from its signed launch configuration
([launch-configuration.md](launch-configuration.md)); elsewhere they are
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
