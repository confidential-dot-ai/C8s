# Secret release

How a workload is authorized to read a secret, and what the allowlist and the
admission inventory contribute to that decision.

## When it is served

Release is gated on an allowlist entry carrying a grant, which is operator-signed
and changeable without a restart. An entry without one releases nothing, so
writing a grant is what turns release on.

Serving the endpoint at all needs what sandbox identity already requires —
`--armtls-platform`, `--measurements`, and node addresses to bound the inventory
callback (`--sandbox-inventory-cidr`, or the live node list it derives when that
is unset). Miss any and CDS logs a warning naming the one it is missing, and
does not serve `/secrets`.

Sizing: `--secrets-max-paths-per-workload` (default 64, chart
`cds.secretsMaxPathsPerWorkload`) bounds the paths one allowlist entry may hold,
and is checked before the ceiling. A workload, for this bound, is one allowlist
entry — which the store calls a holder. `--secrets-max-paths` (default 1024,
chart `cds.secretsMaxPaths`) is the store's memory ceiling; size it above the
number of entries carrying a grant times the per-workload quota, or entries that
arrive late find the store full. The quota must stay below the ceiling: CDS
refuses to start otherwise, and the chart refuses to render
(`VALIDATION_ERROR kind=cds_secrets_path_budget`), so raise the two together.
Operator values count against the ceiling only. Also `--secrets-max-value-bytes`
(at least 32, the size of every value CDS generates) and
`--sandbox-ledger-max-entries`. CDS is a single in-memory process holding the
mesh CA, so a workload able to grow the store without limit could OOM it and
take every certificate in the cluster with it.

**Both bounds refuse the write; nothing is ever evicted.** A path holds the only
copy of its value, so a store at either bound answers `507` and keeps what it
has, carrying `secret_holder_quota` or `secret_store_full` as the error code so
a caller can tell which bound refused it. Raising a bound needs a restart, which
empties the store; see "Restarts".

The quota bounds one entry, not the store: enough entries one path apiece still
reach the ceiling. What it buys is that the refusal lands on the entry that
caused it rather than on the next one to ask.

The fetcher redeems its sandbox token from the mounted nri-image-policy
socket. The webhook rejects `confidential.ai/c8s-secrets` when the operator
has no inventory socket configured, rather than admitting a pod whose fetcher
would CrashLoop while the workload waits for a file that never lands.

## Asking for a secret

Annotate the pod alongside `confidential.ai/cw`:

| Annotation | |
|---|---|
| `confidential.ai/c8s-secrets` | comma-separated `NAME=/store/path`; `NAME` is the file each value is written to |
| `confidential.ai/c8s-secret-dir` | where the files land; default `/run/c8s/secrets` |

```yaml
annotations:
  confidential.ai/cw: api
  confidential.ai/c8s-secrets: "DB=/tenant-a/db,HF=/tenant-a/hf-token"
```

The webhook injects a `c8s-secret` sidecar and a memory-backed volume. Every
container in the pod mounts that volume **read-only**; only the fetcher may
write it. The volume and the container name are reserved — a pod declaring
either is rejected, since a `hostPath` there would write a released secret to
host-visible storage, and an ephemeral container mounting it would read one out
of a running pod.

### The file appears after your container starts

This is the part to design around. CDS releases only once **every** main
container is running, because that is when the sandbox matches a whole workload
entry. The fetcher therefore starts alongside the workload, is refused while the
set is incomplete, and writes when it completes. A consumer must wait for its
file rather than read it at startup:

```sh
until [ -f /run/c8s/secrets/DB ]; do sleep 1; done
```

Nothing can remove this. An init container would be asking before its siblings
exist and would deadlock the pod it gates. The consequence is that a terminal
fetch failure leaves a `Running` pod with no secret and an
`Init:CrashLoopBackOff` sub-status — there is no fail-closed delivery gate to be
had under combination gating.

A workload that finds its path empty creates it, so the first pod of a workload
to ask defines the value.

## The API

The injected fetcher speaks this; a workload does not have to. Every request
needs a single-use challenge and a fresh sandbox token, so a release is bound to
one caller and cannot be replayed.

```
POST /secrets                      → {"challenge": "<base64>"}
GET  /secrets/<store path>         → 200 {"value": "<base64>"} | 404 | 403
POST /secrets/<store path>         → 201 {"value": "<base64>"} | 409 | 403
                                   → 507 {"error": "secret_holder_quota"|"secret_store_full"}
```

`PUT` on the same paths is the operator's, authorized by the operator key
instead — see "Operator-supplied values".

`POST /secrets` is the challenge route; the wildcard can never match it, so no
store path is shadowed by it — a secret at `/challenge` still resolves.

A request carries:

| | |
|---|---|
| client certificate | the pod's mesh leaf, mTLS. Its CDS-stamped sandbox ID is the identity |
| `X-C8s-Challenge` | base64 of the challenge, consumed before anything else happens |
| `Authorization: SandboxToken <base64>` | the inventory-signed token, in a header so it is bounded and never logged |

The token is obtained from the admission inventory at `POST /sandbox` — the
node's inventory — bound to the leaf's key and
that challenge, the same route and the same envelope `get-cert` uses at
issuance.

**`POST` never carries a value.** CDS generates it, so no caller chooses what
another caller will later read. On a path that already exists it answers `409`
with **no body**: returning the value would make a write grant a read grant. A
caller holding `read` recovers with `GET`, which is how the replica that loses
a create race gets the value.

A path that is not granted is `404`, indistinguishable from one that does not
exist — otherwise the API enumerates the store. Denials are opaque to the
client; the reason goes to the CDS log.

**These routes are rate-limited per sandbox**, keyed on the ID in the verified
client certificate. Pods reach CDS through a NodePort and the host-network mesh
proxy, so every pod on a node arrives from the node's address: bounded on that,
one pod could spend the budget its co-tenants share and hold their fetchers in a
CrashLoop. A request whose certificate is absent or unverified is bounded by
address instead — it is refused by the handler regardless, and a caller cannot
opt out of the limit by withholding an identity.

Paths must arrive already canonical: absolute, clean, no trailing slash, and no
percent-encoding. They are rejected rather than repaired, so the bytes matched
against a grant and the bytes used as a store key are the bytes the client
sent.

## Operator-supplied values

CDS generates a value it is asked for and finds missing, which covers a session
key but not an API token, a database password, or a wrapped key. Those come from
an operator:

```sh
c8s secrets put /tenant-a/hf-token --url "$CDS" --measurements "$M" \
  --mesh-ca mesh-ca.pem --operator-key operator.key < token.txt
```

The value is read from stdin or `--from-file`, and the bytes are stored exactly
as read — a trailing newline is part of the value. The byte count is printed to
confirm which one was sent.

### Naming the CDS you are writing to

`--mesh-ca` takes the CA bundle you hold out of band, the same anchor
`c8s verify --mesh-ca` takes. Before the write, the CLI reads the mesh CA CDS
serves at `GET /ca` over the attested connection and refuses unless it is one
you pinned.

`--measurements` alone does not cover this. It proves the peer is an attested
build at a pinned launch measurement — but nodes can boot the same image,
so that measurement does not identify a particular CDS instance. The mesh CA key is generated per CDS, so it is what tells your CDS from
another one at the same measurement, and it is the anchor your workloads
already trust.

The write is refused with no `--mesh-ca`. `--force` writes without the check
and says so on stderr; it governs the CA check only, and is unrelated to
`--overwrite`, which governs replacing a value already at the path.

### Reading the mesh CA bundle

`c8s cds ca` reads the bundle over the same attested connection the write uses:

```sh
c8s cds ca --url "$CDS" --measurements "$M" --out mesh-ca.pem
```

Endpoint pins are required: use `--image-policy-file` for a complete image
policy, or `--measurements` / `--measurements-file` for launch digests. Pin CDS
for a direct URL or the router for a front door. The SHA-256 of each certificate
goes to stderr.
Record it. The read proves an attested build at `$M` served these bytes, which
is the bound the gate has too: comparing that digest against an earlier read, or
against a copy taken another way, is what separates your CDS from another one at
the same measurement.

`GET /ca` carries every CA CDS still signs leaves against, newest first, and the
gate wants all of them — so pin the whole bundle. Without `--out` it goes to
stdout instead.

CDS generates its mesh CA in process and a restart replaces it (see
[operator.md](operator.md), "CDS is a singleton"), so read the bundle once CDS
has settled. A bundle captured before a restart reads afterwards as the CDS
serving a mesh CA that is not in `--mesh-ca` — the same refusal as the wrong
CDS.

```
PUT /secrets/<store path>   {"value": "<base64>", "overwrite": <bool>}
                            → 201 {"created": true}
                            → 409 {"existing": "workload"|"operator"}
                            → 200 {"existing": "workload"|"operator"}
                            → 507 {"error": "secret_store_full"} the ceiling refused it
```

Authorization is the operator key that CDS already pins for allowlist writes
(`cds --operator-keys`) — the same key the `secrets` grants are rooted in. Its
token binds the method, path, and body, so a captured one cannot be replayed
against a different path or a different value. `overwrite` travels in the body
for that reason: a query parameter is outside what the token covers.

### Replacing a value

A path that already holds a value answers `409` and names what put it there —
a workload that found the path empty, or an earlier operator write. Nothing is
written. `--overwrite` replaces it, and the CLI prints what it is replacing
before it does:

```
$ c8s secrets put /tenant-a/db --overwrite < db.txt
~ /tenant-a/db (replaces a workload-generated value)
wrote 24 bytes to /tenant-a/db
```

The store has no versioning and no delete, so a displaced value is gone.

**A workload reads its secret into a file once, at startup.** Replacing a value
reaches a pod when that pod next restarts, so a Deployment holding the old value
keeps it until it is rolled. Replacing a path a workload created is worth
pausing over for that reason: the pods that generated the value go on using it.

Revoking a value means restarting CDS, which empties the whole store — see
"Restarts".

## Diagnosing a refusal

A refused pod is told only that it was refused, and the set that decides the
matter — what the sandbox is running — is visible only to CDS. `explain` is
where that is read:

```sh
c8s secrets explain --sandbox "$ID" --url "$CDS" --measurements "$M" \
  --operator-key operator.key
```

```
sandbox    0123456789abcdef…
inventory  10.0.0.7
reported   3 container(s)
dropped    1 injected by c8s
candidates 2
    sha256:1111…  [/serve]
  - sha256:9999…  [get-secret]
    sha256:8888…  [sh -c sleep 1]

vllm-llama  NEAR MISS
  foreign  sha256:8888…  [sh -c sleep 1]
           no container in this entry declares it

nothing is released: no entry describes the candidate set
```

The sandbox ID is on the pod's certificate; `c8s verify` prints it. `--json`
emits the report as it arrives.

It reads the same inventory, binding and allowlist the release path reads, and
measures entries with the same matcher, so it reports the decision rather than a
reconstruction of it. It answers to the operator key, since it describes a pod
the caller may not own. The report carries grant paths; a value never appears in
it.

`GET /secrets-explain/{sandboxID}` is a sibling of `/secrets`, not a path under
it: a literal segment beats the wildcard in routing, so mounting it below
`/secrets` would make every secret stored under that prefix unreachable.

## What CDS checks

1. The client certificate chains to the mesh CA — verified by crypto/tls, not
   by the handler. Embedded-evidence verification of a self-signed certificate
   is insufficient here: its sandbox-ID extension is peer-chosen.
2. The sandbox ID comes from that verified leaf.
3. The sandbox token verifies against the inventory **bound to that sandbox**,
   carries this request's challenge, and names the same sandbox as the leaf.
4. That inventory reports what the sandbox has run.
5. The reported set, minus injected containers, matches exactly one workload
   entry.
6. That entry's grant covers the requested path.

Any failure refuses. So does an unreachable inventory, an unknown sandbox, an
empty container set, an ambiguous match, or an entry with no grant.

### Which inventory is asked

The binding is CDS's, not the requester's. At issuance — where the token has
already been verified — CDS records `sandbox ID → inventory host`,
**first-write-wins**, and the secrets path dials *that* host. The token must
name the same one.

This matters because a token is signable by anything that can answer on the
inventory port inside the configured CIDRs. Taking the host from the request
would let such a thing sign a token for someone else's sandbox, be believed
about what that sandbox runs, and have the answer used to release its secrets.

A conflicting binding does **not** refuse a certificate. `get-cert` has no
token-less retry, so denying at issuance would let one pre-claim wedge a pod for
a whole certificate lifetime — worse than what it prevents. The sandbox is
instead unusable for secrets, which costs one workload rather than every pod on
the node.

### The injected drop set

C8s injects its own containers into every confidential pod. They are not part of
a workload's declared set, so they are removed before matching — an entry never
has to enumerate C8s's own sidecars.

A container is dropped when its digest is admitted by some entry under an
**unconstrained argv policy** (`command` and `args` both `any`) *and* its
entrypoint is one C8s injects (`get-cert`, `get-secret`, `get-volume`, `/c8s`).
Both halves are load-bearing. Admission alone would let a pod add any
any-argv component image with its entrypoint overridden — and have it ignored.

The seeded component entries are the source: the injected image is among them,
since it could not run otherwise, and an image bump seeds the new digest's entry
beside the old one ([`allowlist-and-capabilities.md`](allowlist-and-capabilities.md#bootstrap)).

What this rests on, in both directions: no image admitted under an unconstrained
argv other than C8s's has an executable at one of those entrypoints, and the
injected image's own entry stays unconstrained — an operator who narrows it
(`bootstrapAllowlist.workloads` or `c8s allowlist edit`) turns every injected sidecar
into a foreign container and every release in the cluster is refused. Allowlist
contents are operator-controlled and auditable, but that is a property of the
deployment rather than something enforced here.

## The grant

A secret grant belongs to a **workload entry**, not a container:

```json
"vllm-llama": {
  "containers": [ { "digest": "sha256:…", "command": {…}, "args": {…} } ],
  "secrets": { "policy": "allow", "read": ["/tenant-a/**"], "write": ["/tenant-a/session"] }
}
```

The subject is the entry because the value is delivered on a volume every
container in the pod can read — a per-container grant would not describe what is
actually released.

- `policy` is `allow` or `deny`. There is deliberately **no `any`**: an unbounded
  secret grant is never what an operator means.
- A grant requires every container in the entry — init and main — to pin its
  argv: `command` and `args` both `exact` or `deny`. A container under `any`
  runs whatever command line the host chose, and the value would be released
  to it. The write path refuses the entry, and release refuses an entry stored
  before it did.
- Paths are absolute, clean, and the only wildcard is a trailing `/**`, which
  matches strictly beneath its base — `/a/**` does not grant `/a`.
- `write` requires `read`. The only client creates with `POST`, then re-reads;
  a write-only grant would strand every replica that loses the create race.
- A grant that releases nothing is **omitted** from the canonical document, so an
  entry without one carries no `secrets` key and a consumer that does not know
  the field never sees it.

The in-pod destination of a secret is **not** an authorization boundary — the
workload owns its own filesystem once the value is inside it — so only the store
path is policy.

### Upgrading

CDS parses its seed with unknown fields rejected and fails closed, so a values
file still carrying per-container `paths` would stop CDS booting. The chart
rejects it at `helm upgrade` (`VALIDATION_ERROR kind=allowlist_container_paths`).
Move the grant up to the entry; a `deny` grant is simply dropped.

Serving the field is safe ahead of the consumers: `secrets` appears only once an
operator writes a real grant, and the pull path
(`allowlist.ParseServedJSON`) ignores fields it does not know. Strict parsing is
kept for operator-authored input, where an unknown field is a typo.

## The mount policy

Every container in the entry also needs a `mounts` policy admitting what the
webhook injects: the cert volume, and the secret directory. An absent policy is
`deny`, which admits platform mounts alone and so refuses the pod at container
creation.

Both are memory-backed `emptyDir`s, so an `exact` policy names them by
destination:

```json
"mounts": {"policy": "exact", "rules": [
  {"destination": "/etc/c8s/certs", "kind": "emptyDir"},
  {"destination": "/run/c8s/secrets", "kind": "emptyDir"}
]}
```

The destinations follow `confidential.ai/c8s-cert-dir` and
`confidential.ai/c8s-secret-dir` where the pod sets them. `exact` is set
equality, so the rules also cover every other non-platform mount the pod
declares; a configMap, projected or PVC source classes as `data`, whose
destination sits below `/mnt/c8s-data/`.

`{"policy": "any"}` admits any mount table, leaving the host free to add one.
It is what the chart seeds for C8s's own components. See
[`allowlist-and-capabilities.md`](allowlist-and-capabilities.md#mount-policy-mounts).

## What the inventory reports

`GET /digests/{sandboxID}` answers with two views of the same sandbox:

| field | contents | used by |
|---|---|---|
| `digests` | image digests | cert issuance (membership) |
| `containers` | image digest and launch evidence: `argv`, `env`, `mounts` | secret release |

Both views omit duplicates. An image appears once in `digests`, but can have
multiple records in `containers` if it ran with different launch evidence.

`argv` is the effective OCI `process.args` a container runs, so release can hold
a sandbox to the `(digest, argv)` pairs that ran in it rather than to a digest
set that says nothing about what those images were told to run.
Without it, two entries differing only in argv are indistinguishable, and the
argv admission enforces is a **union across every entry listing the digest** — so
an entry that pins `command: exact` gives no guarantee at release time if another
entry widens the same digest.

The mount evidence records each destination's observed class and storage. Its
node-local source path is deliberately omitted from the inventory response;
host mounts carry a source commitment and read-only mode.
`mounts: []` means no bind mounts were observed. `mounts: null` or a missing
`mounts` field means mount evidence is unavailable; exact and deny mount
policies fail closed in that case. Inventory responses retain the `mounts` field
even for an empty set so consumers can preserve this distinction.

`containers` is absent on an inventory older than the field. A consumer that
needs it must treat that as "cannot answer" rather than "no containers"
(`RequireContainers`).

### The report is a high-water mark

Both views describe every container **ever admitted** in the sandbox, not those
running now. The inventory is otherwise "created and not yet removed", and
kubelet removes and recreates a container across a `CrashLoopBackOff` — so a live
snapshot lets a pod arrange for a container to be absent at the moment it is
asked and present a set it does not have. A pod could then declare a victim
entry's containers plus one extra image that exits immediately, be handed the
secret during a backoff window, and read it when the extra container restarts.

Admission is monotone, so membership here is too. A container that stops leaves
caller resolution — a stopped container must not bind a caller — but stays in the
sandbox's record until the sandbox itself is torn down.

The cost is that a pod which ever ran an image outside its entry never receives a
secret, even after that image is gone. That is the correct direction for a
release decision.

## Restarts

**A CDS restart destroys every secret, and requires rolling every workload that
holds one.**

The store is process memory and there is no persistence. Worse than losing it:
a pod recreated after the restart calls `POST`, finds the path empty, and is
given a **new** value — while its siblings still hold the old one. Nothing
reports this. A partially-rolled Deployment ends up with two different values
for one path.

So after a CDS restart, restart every secret-consuming workload rather than
letting them recover piecemeal — a rolling restart of each Deployment. Treat a released value as ephemeral for the
lifetime of the CDS process; nothing durable may be keyed on one.

The sandbox ledger is process memory too, so a leaf that outlives a restart has
no binding until its next renewal and is refused meanwhile.
