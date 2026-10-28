# Security model

How C8s holds up position by position: what an adversary in each position can
attempt, and the defence that stops it, with its owner page and guarantee.

Guarantee: all six of them — [guarantees.md](guarantees.md).

The trust boundary and what is trusted without proof are
[overview.md](overview.md#trust-boundary-and-adversary), which also holds the
non-goals: availability, side channels, and physical attacks. Terms are
defined in [glossary.md](glossary.md).

## The host and its hypervisor

The host runs the node, owns its storage and network, and can run genuine TEEs
of its own.

- **Read or alter the node's memory**: the node is the confidential VM, so the
  CPU encrypts its memory and its pods are processes behind that boundary
  ([overview.md](overview.md#node-as-cvm));
  [Data stays in the TEE](guarantees.md#data-stays-in-the-tee).
- **Boot modified node software**: the launch measurement names what booted and
  a verifier states which measurements it accepts, which on TDX takes runtime
  registers beside the firmware measurement ([measurements.md](measurements.md),
  [armtls.md](armtls.md#the-handshake-and-pin-checks));
  [Identity comes from hardware evidence](guarantees.md#identity-comes-from-hardware-evidence).
- **Answer as a TEE of its own, or with a recorded report**: in-cluster armTLS
  refuses a pin set naming no guest before any request, and an issuance binds a
  single-use challenge into the report ([armtls.md](armtls.md#cds-issuance));
  [Identity comes from hardware evidence](guarantees.md#identity-comes-from-hardware-evidence).
- **Relaunch a node with other settings**: the `c8s-launch/v1` document is
  signed over its exact bytes and the launch key's public half binds into its
  evidence ([launch-configuration.md](launch-configuration.md),
  [operator.md](operator.md#authenticated-launch-configuration));
  [Identity comes from hardware evidence](guarantees.md#identity-comes-from-hardware-evidence).
- **Edit or roll back a volume's ciphertext**: an immutable volume's dm-verity
  tree sits inside the encryption, so a changed block surfaces as an I/O error,
  and the wrong disk fails closed on the key or the root hash; a `--mutable`
  volume has no tree, so keep such data immutable ([volumes.md](volumes.md));
  [Data stays in the TEE](guarantees.md#data-stays-in-the-tee).

In router mode `webpki` the public-TLS key is an operator Secret the host can
read, so the router refuses attest-lb, the attested handshake that binds the
serving leaf of a client's own connection: clients that need it must run mode
`cds` or `acme` ([operator.md](operator.md#the-router)).

## The Kubernetes control plane and the cluster administrator

This adversary holds the control plane and the credential `c8s get-kubeconfig`
releases: it can create any pod and edit every object that credential reaches.

- **Admit a pod running other code**: admission runs in the node CVM below the
  API server, keyed on image digest, at container creation, adjustment
  validation, and start, with the plugin a required validator so nothing starts
  while it is disconnected; a pull applies only at or above the version last
  applied, so withholding one restores no laxer policy while that plugin lives
  ([allowlist-and-capabilities.md](allowlist-and-capabilities.md#where-and-when-it-is-checked));
  [Only allowlisted code runs](guarantees.md#only-allowlisted-code-runs).
- **Hand an allowlisted image node root**: the measured node image denies host
  namespaces, foreign bind mounts, devices, hooks, and sysctls at start, and
  `c8s-runc` bounds every container of a member pod, the runtime's own sandbox
  aside
  ([allowlist-and-capabilities.md](allowlist-and-capabilities.md#host-privilege),
  [node-exec-mode.md](node-exec-mode.md#the-privilege-floor));
  [No privileged way in](guarantees.md#no-privileged-way-in).
- **Exec, attach, or debug into a pod**: the measured node image denies
  `pods/exec`, `pods/attach`, `pods/portforward`, and
  `pods/ephemeralcontainers` for every principal, and `c8s-runc` refuses the
  `exec` verb ([node-exec-mode.md](node-exec-mode.md));
  [No privileged way in](guarantees.md#no-privileged-way-in).
- **Escalate with the released credential**: its ClusterRole is enumerated,
  and a baked admission policy re-checks the same exclusions for every
  principal in a `c8s:` group — the RBAC groups those credentials carry —
  refusing writes in the privileged namespaces, takeovers of a platform
  address, and the kubelet-proxy subresources
  ([operator.md](operator.md#bounded-operator));
  [No privileged way in](guarantees.md#no-privileged-way-in).
- **Write policy or routes of its own**: a write needs a single-use operator
  signature over that exact method, path, and body, made outside the cluster
  ([allowlist-and-capabilities.md](allowlist-and-capabilities.md#writing-policy)).
  A baked node — one booted from the measured node image — takes the operator
  keys from its launch configuration; elsewhere they are cluster configuration,
  so pin the route digest or those keys
  ([operator.md](operator.md#route-manifest));
  [Only allowlisted code runs](guarantees.md#only-allowlisted-code-runs),
  [Routes are what the operator signed](guarantees.md#routes-are-what-the-operator-signed).
- **Issue a workload certificate**: only CDS — the Certificate Distribution
  Service, the one in-cluster pod holding C8s policy — signs leaves, and its
  mesh CA key lives only in process memory, never in a Kubernetes Secret
  ([armtls.md](armtls.md#cds-issuance));
  [Identity comes from hardware evidence](guarantees.md#identity-comes-from-hardware-evidence).

The node-side defences above are the measured node image's. On the chart lanes
(`gke`, `aks`) the plugin's own base allowlist and mode, the host-namespace
policy, and the exec path are chart values the same administrator writes
([overview.md](overview.md#cvm-modes-and-hardware-platforms)), so an
adversarial administrator means the measured node image. Deleting CDS drops the
served entries, the secrets, and the route manifest, after which every member
pod must be recreated ([operator.md](operator.md#cds-is-a-singleton)).

## The pod network

- **Read or alter pod traffic**: a member pod's TCP is captured into its mesh
  endpoint and carried over armTLS, ALPN `c8s-mesh/1` required and session
  resumption off ([armtls.md](armtls.md#the-mesh-endpoint-profile));
  [Data stays in the TEE](guarantees.md#data-stays-in-the-tee).
- **Impersonate a peer**: the mesh admits a peer only on a leaf chaining to the
  mesh CA, which proves that peer's measurement at issuance, not at handshake
  ([armtls.md](armtls.md));
  [Identity comes from hardware evidence](guarantees.md#identity-comes-from-hardware-evidence).
- **Dial a pod around the mesh, or have it dial out**: the node's packet rules
  deny both directions except five named kinds, and reach beyond the mesh is
  the `egress` its entry names ([allowlist-entries.md](allowlist-entries.md));
  [Only allowlisted code runs](guarantees.md#only-allowlisted-code-runs).

Two of those kinds are C8s's own plaintext — resolver queries, and the baked
cluster-metrics Service, readable by any member pod on a measured node
([armtls.md](armtls.md#cluster-metrics)) — and a pod's declared egress is the
third way out in the clear.

## Another tenant's pod

- **Obtain a certificate naming another pod**: the sandbox token comes from the
  node's admission inventory over a node-local socket that identifies the
  caller by kernel peer credentials, and binds the sandbox, the key, and the
  challenge ([getcert-workload-binding.md](getcert-workload-binding.md));
  [Identity comes from hardware evidence](guarantees.md#identity-comes-from-hardware-evidence).
- **Collect another workload's secret, or have its volume opened**: release
  needs a leaf chaining to the mesh CA, a fresh token naming that sandbox, an
  inventory report matching exactly one entry, and a grant covering the path
  ([secrets.md](secrets.md#what-cds-checks)); volumed mounts only into the
  calling pod's own directory ([volumes.md](volumes.md#opening-a-volume));
  [Data stays in the TEE](guarantees.md#data-stays-in-the-tee).
- **Vouch for a sandbox itself**: answering as the inventory takes privileged
  port 1019 at the node's address, which takes host networking or a host port,
  given to no tenant pod, plus evidence CDS's pins accept from an address the
  operator's inventory set names — and whatever holds all that can sign for any
  sandbox that node admitted ([armtls.md](armtls.md#sandbox-identity));
  [No privileged way in](guarantees.md#no-privileged-way-in).

A node is one trust domain: its pods share its TEE, and possession of a key
blob authorizes a volume, so tenants that do not trust each other belong on
separate nodes and volume workloads need single-tenant ones.

## A compromised workload

- **Break out to the node**: on a measured node the privilege floor bounds
  capabilities, keeps `no_new_privs` set, and refuses user namespaces and the
  privileged marks; the chart lanes have only the chart's cluster policy
  ([node-exec-mode.md](node-exec-mode.md#the-privilege-floor));
  [No privileged way in](guarantees.md#no-privileged-way-in).
- **Keep its name after running foreign code**: the inventory report is a
  high-water mark over every container ever admitted in that sandbox, so the
  pod issues unnamed from then on and a named leaf lives at most 6 hours
  ([armtls.md](armtls.md#matched-workload),
  [secrets.md](secrets.md#the-report-is-a-high-water-mark));
  [Only allowlisted code runs](guarantees.md#only-allowlisted-code-runs).

Admission bounds what runs, not what running code does with the data it holds,
and a measurement covers boot state, so runtime compromise inside a measured
node is out of scope. Pin every container of an entry that holds a grant.

## The software supply chain

- **Serve other bytes under a release tag**: a release publishes
  `release-statement.json` with a Sigstore bundle signed keyless through GitHub
  Actions, naming the commit, the tag, and each allowlist seed's SHA-256
  ([releases.md](releases.md#verify-a-release));
  [Anyone can verify it](guarantees.md#anyone-can-verify-it).
- **Move a tag under a running cluster**: every admission decision keys on the
  image digest, and node images get no moving release alias, so pin the exact
  `-vX.Y.Z` image whose measurement you accept ([releases.md](releases.md));
  [Only allowlisted code runs](guarantees.md#only-allowlisted-code-runs).

Production node images carry kernel modules signed with a private key, so an
outsider cannot rebuild one bit for bit. Pins come from the published image
build, which `c8s measurements derive` turns into a measurements config
([measurements.md](measurements.md)).

## Public clients

- **Be answered by a lookalike**: the client runs an attested handshake —
  attest-lb on its own connection, or attest-pq, which over-encrypts its
  requests inside ordinary TLS — and checks the evidence against its pins
  ([verify.md](verify.md), [routes-evidence.md](routes-evidence.md));
  [Anyone can verify it](guarantees.md#anyone-can-verify-it).
- **Be routed somewhere the operator did not sign**: the router routes by the
  signed manifest alone — 503 before one is applied, 404 off it — and dials a
  workload backend only on a leaf carrying that route's workload name under the
  allowlist digest its own leaf carries, where CDS stamped one
  ([operator.md](operator.md#route-manifest));
  [Routes are what the operator signed](guarantees.md#routes-are-what-the-operator-signed).
- **Move a session after its handshake**: a session routes by the manifest and
  router allowlist digest that handshake bound; once either changes the router
  answers 503 and the client attests again
  ([routes-evidence.md](routes-evidence.md#session-binding));
  [Routes are what the operator signed](guarantees.md#routes-are-what-the-operator-signed).

A verdict covers one connection to one replica at one instant, so each client
verifies its own connection rather than reusing another's receipt.
