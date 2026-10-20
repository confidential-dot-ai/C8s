# Conformance harness

The executable half of an external conformance suite: Gherkin scenarios,
maintained outside this repo, are run against a live c8s cluster by the step
definitions in [`steps/`](steps), which observe the cluster through the
backends in [`backends/`](backends). The scenarios and their judge are not
here; this directory holds what has to move with c8s.

## Step definitions

[`steps/`](steps) is its own Go module in `go.work`. Each Gherkin sentence
maps to one function; a step calls backend functions, `kubectl`, and the `c8s`
CLI, never c8s packages, so the suite stays a black-box check of the running
cluster. The one library the steps share with c8s is `attestation-go`, for
the wire format of the evidence a certificate carries, which is not c8s's to
change. A new sentence is a new step here; a scenario reusing existing
sentences needs no change in this repo.

`TestFeatures` is the entry point. It runs only when the runner sets:

| Variable | Meaning |
|---|---|
| `CONFORMANCE_FEATURES` | the directory of `.feature` files to run |
| `CONFORMANCE_BACKEND` | the backend, `kind` or `metal` |

godog's own flags are bound under `--godog.`: `--godog.format=cucumber:report.json`
writes the report the runner records, `--godog.tags=@area:enforcement` selects.

## Probes the steps exec

Where a scenario needs the cluster to see a request no well-behaved client
sends, the steps exec a probe built into the `c8s` binary that is already in
the pod. `c8s secret-probe` (`internal/cmds/secretprobe`) is hidden from
`c8s --help` because it is a test instrument, not a client for applications:
run with `kubectl exec -c c8s-cert <pod> -- /c8s secret-probe --cds-url URL
--attestation-api-url URL --cert FILE --key FILE <action>` inside the injected
certificate sidecar, it performs one workload secret request with every input
under the caller's control. It verifies the CDS as the sidecars do, through
armTLS against the pins it is given; the steps give it the attestation API and
pins the webhook gave that container. `challenge` fetches a fresh CDS challenge and prints it base64;
`token` redeems a sandbox token for the pod's sandbox from the node's
inventory socket, bound to the leaf's key and to a given challenge, and prints
the JSON the Authorization header carries; `request <GET|POST> <path>` sends the
request with `<path>` verbatim, a fresh or given challenge or none, and a fresh
or given token or none, then prints one line with the HTTP status (`000`
when nothing answered, a CDS that issued no challenge included) and the
challenge and token it sent, base64 or `-` for a header it omitted, and the
body after it, exactly as received. It exits 0 whenever an answer was printed
and 2 when it could not ask, so a scenario about a missing or replayed
challenge, another pod's token, or a non-canonical path reads the CDS's
verdict rather than a sidecar's refusal to send it, and "that request's"
challenge is known without a separate fetch. `c8s secret-probe --help` has
the flags.

An instrument that must run inside a container c8s owns (the certificate
sidecar's image is the c8s image, with nothing else in it) is a hidden `c8s`
subcommand; one that is a peer in a pod of its own is an image under
[`tools/`](tools).

Where a backend cannot exec into a pod whose argv and mounts a scenario pins,
it reads the pod's files from the pod's log instead. The reporter image
([`images/reporter`](images/reporter)) is `image_ref`'s model-server with the
reporter as its `sleep`: it sleeps as asked and, while it does, prints each
file of the certificate volume but the key, and of the secret client's output
directory, as `c8s-report file <path> <base64>` when it appears or changes,
and that directory's filesystem type, as `c8s-report fstype <dir> <type>`.
[`conformance-images.yml`](../../.github/workflows/conformance-images.yml)
builds it on dispatch, and a backend pins its digest.

## Running

[`run.sh`](run.sh) is what the suite's judge runs as its test command. It sets
the backend up, runs `TestFeatures` with a Cucumber report, and tears the
backend down, reading:

| Variable | Meaning |
|---|---|
| `CONFORMANCE_BACKEND` | the backend, `kind` or `metal`, plus whatever that backend requires |
| `CONFORMANCE_FEATURES` | the directory of `.feature` files to run |
| `CONFORMANCE_REPORT` | where to write the Cucumber JSON report |
| `GODOG_TAGS` | optional tag expression, such as `@area:enforcement` |

It exits with godog's status, so a failed step fails the command; undefined
and pending steps are the judge's backlog and do not.

## Backends

A backend answers a fixed set of questions about one running environment so
the steps need not know how it was built: which Kubernetes node stands behind
a scenario's "node one", which pullable reference and digest a scenario's
"nginx" means, what the CDS serves, whether the admission plugin on a node is
registered and ready and how often it pulls, whether the node's base allowlist
names a digest, which containers a node's runtime holds for a digest, and a
Restricted-compatible pod manifest to deploy. It also acts for the operator:
when a scenario says the plugin has applied the served allowlist, the entries
it described are written through the backend's signed path, and they are
undone after the scenario. The steps then poll the allowlist version the
plugin reports on its health endpoint until it is the served one, within three
pull intervals of the write; where the backend cannot reach the plugin, or the
plugin is meant to ignore what is served, they wait two intervals out instead.

A backend also acts on the node and the CDS where a scenario asks: it stops
and starts a node's plugin, makes the CDS unreachable for the plugins' pulls
and undoes that, and restarts the CDS. Each is undone after the scenario, and
a plugin is started again wherever the CDS was restarted, since a plugin only
accepts the versions a restarted CDS serves after a start of its own. The
mesh is restarted after a CDS restart too: a restarted CDS mints a new mesh
CA, which only a proxy started after it accepts.

Where a scenario is about the CDS's own API, the backend sends the request as
the scenario says rather than through its signed path: a write with the
Authorization a caller holds, or none; a read naming a version; the write
token minted with the operator's key or with a key that is not an operator
key, and for a chosen lifetime. It also answers whether the CDS holds an
operator key, whether its seed names a digest, and what argv an image starts
with.

For scenarios about issuance, the backend renders two more pods: one carrying
a workload ID, whose requester the webhook injects and which the steps watch
through the files of its certificate volume and its requester's log, and a
requester the steps drive themselves, a pod that relays HTTP from inside the
cluster so the CDS sees the pod's own source address, and that can reach the
node's sandbox inventory and local attestation service over the socket
directory the admission plugin binds into it. The backend also fetches
evidence over chosen report data (and, where the attestation is mocked, over
a chosen launch digest), reads the CDS's flags, restarts it with IP SAN
binding or an inventory address range changed, names a pod's runtime sandbox,
and runs the operator's verifier as a relying party on a saved leaf.

For scenarios about the CDS itself, the backend reads its documents and its
serving certificate as any client would, says what it was started with,
restarts it with one parameter changed and restores it, stops the local
attestation service of its node, searches the cluster for private keys and
performs one issuance against it; `common.sh` lists each function. The kind
backend reaches the CDS through a port-forward to its pod, so a CDS that is
not ready, and so has no Service endpoint, is still read.

For scenarios about the armTLS mesh, the backend reads the node's mesh proxy:
whether it is running, whether a pod address is in the node's interception or
guard membership, its connection and guard-drop counters (scraped from the
proxy's health port by a long-lived pod the backend keeps in its own
namespace, torn down with the backend), its listener ports, the UIDs and
namespaces it excepts, whether each role presents a CDS-issued leaf, and
whether its verify set has taken the mesh CA. It renders pods with the options
the mesh scenarios need (the node's network namespace, a chosen UID, a
capability, a label, an init container), serves a hello API at an address
outside the cluster, and blocks the node's local attestation service. Every
pod it renders may ping: the pod carries the `net.ipv4.ping_group_range`
sysctl, and the tenant image's ping (Alpine's) uses an ICMP datagram socket
under it, which the library busybox image's does not. A peer that connects to the inbound
proxy itself, presenting a certificate the scenario shaped, is
[`tools/armtls-dial`](tools/armtls-dial/README.md), which the backend builds
for the node's architecture and the steps copy into a pod of the logical
image `mesh-dialer`.

For scenarios about secret release, the backend sends one request to the CDS
as the scenario shaped it (`cds_request`: a method, a route, a body, an
Authorization and a client certificate, each only when given), which carries
the operator's secret writes under the write tokens `write_token` mints and a
self-signed requester's read. The workload requester is `c8s secret-probe`,
exec'd by the steps in the pod's certificate container (below); the secret
client's files are read through the pod's first container. Secret paths are
logical: a scenario's `/models/key` lives under a per-scenario prefix, since
the store has no delete and outlives the scenario. A pod carrying a workload
ID that a secrets scenario (one tagged `@area:secrets`) deploys renews its
leaf every two hours rather than the ten seconds an issuance scenario's pod
does, so the leaf it obtained stays the one it holds.

Route manifest scenarios write `PUT /routes` through `cds_request`, with an
`If-Match` header where the scenario names a route digest, and reach the
router through `router_request` with a `Host` header. Their hosts are logical:
`app` is a name under the scenario's namespace. A manifest the router is to
apply also routes a probe host named for its revision to a closed address
backend, and the steps wait until the probe answers 502, which no earlier
manifest gives it. The CDS removes no manifest, so after the scenario the
steps write the one stored before it again, or an empty one, under a later
revision. A workload backend is a pod of `tenant-app` running a Python echo
API over TLS under the leaf it holds, read again for each connection: it
answers every request with the request target and headers it received.

[`backends/common.sh`](backends/common.sh) states the interface: every
function, its arguments, what it prints, and when it answers *unsupported*:
exit status 77 (`UNSUPPORTED`), meaning "this environment cannot express
that", which the steps turn into a skip, never a pass. It also
implements the functions that are the same everywhere. A backend sources it,
sets `PLATFORM`, defines what differs, and ends with `dispatch "$@"`, which
rejects unknown names.

| Backend | Environment | Requires |
|---|---|---|
| [`kind.sh`](backends/kind.sh) | the kept kind cluster of [`test/integration/cluster/run.sh`](../integration/cluster/run.sh) (`C8S_IT_KEEP=1 C8S_IT_SETUP_ONLY=1`); mocked attestation, node shell via `docker exec`; the mock signs nothing and verifies only at the mock, so `evidence_unsigned` and `relying_party` answer unsupported; the CDS reads its seed ConfigMap once, as on any chart-managed install, so `seed_add` answers unsupported | `C8S_IT_WORKDIR`; `go` for `dialer_bin` |
| [`metal.sh`](backends/metal.sh) | the attested node image a metal lane booted (`snp-metal-e2e`, `tdx-metal-e2e`), from its `extra-suite` hook; what it cannot reach answers unsupported ([below](#the-metal-backend)) | `KUBECONFIG`, `C8S_ALLOWLIST_URL`, `C8S_OPERATOR_KEY`, the `c8s` CLI on `PATH`; `go` for the write-token functions, `crane` for `image_entrypoint` and `image_env` |

The backends source the kind harness's `lib.sh`, render pods with
`pod-fixture.py`, and name components (the NRI DaemonSet, its socket) that
change with c8s. The tools under [`tools/`](tools) are built by the backends,
copied into pods by the steps, and may import c8s packages: they stand in for
peers the cluster does not have, not for the steps' judgement. A change to any of those updates the backend in
the same PR.
`shellcheck` runs over them and `run.sh` in the node-guest-image lint workflow.

### The metal backend

On a metal lane the harness host has no node shell and no TEE, the
operator's credential may neither exec, port-forward, write Node objects nor
write in the privileged namespaces (kube-system, local-path-storage, c8s-system),
the only ones admitting host-network and root pods, and the node image holds
the seed and the router's configuration.
A function the backend cannot answer some other way under those limits
answers unsupported, which the steps report as a skip, so the scenarios that need it are
reported as not run on metal, never as passed; the skipped step carries a
`skip-reason` attachment naming the function, as does a step that skips
for a precondition the environment lacks. Pod exec is closed too, so `pod_exec` answers agent: a pod the
steps mark `c8s-conformance/harness-argv`, because they chose its first
container's argv, runs an agent there in place of that argv, and `agent_exec`
reaches it. Pods whose argv a scenario pins are read from a reporter image's
log instead. [`metal.sh`](backends/metal.sh) gives each function's answer and
its reason beside the function.

## What is a coordinated change

The suite calls `run.sh` and the backends by name. Renaming a backend
function, changing its arguments or output, or changing the variables `run.sh`
and `TestFeatures` read is a coordinated change with the suite's judge
configuration. Adding a step or a backend function is not.

Nothing here runs a scenario in this repo's CI: `make test` compiles the steps
and `TestFeatures` skips. The suite's own CI runs the steps on kind and on both
metal lanes.
