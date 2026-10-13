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
undone after the scenario. The plugin exposes nothing about the allowlist
version it holds, so the steps wait until two pull intervals have passed since
the last write before acting on it, and read the served version then.

A backend also acts on the node and the CDS where a scenario asks: it stops
and starts a node's plugin, makes the CDS unreachable for the plugins' pulls
and undoes that, and restarts the CDS. Each is undone after the scenario, and
a plugin is started again wherever the CDS was restarted, since a plugin only
accepts the versions a restarted CDS serves after a start of its own.

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
[`tools/armtls-dial`](tools/armtls-dial/README.md), run inside a pod of the
image the backend builds for the logical image `mesh-dialer`.

[`backends/common.sh`](backends/common.sh) states the interface: every
function, its arguments, what it prints, and the exit status that means "this
environment cannot express that", which the steps turn into a skip. It also
implements the functions that are the same everywhere. A backend sources it,
sets `PLATFORM`, defines what differs, and ends with `dispatch "$@"`, which
rejects unknown names.

| Backend | Environment | Requires |
|---|---|---|
| [`kind.sh`](backends/kind.sh) | the kept kind cluster of [`test/integration/cluster/run.sh`](../integration/cluster/run.sh) (`C8S_IT_KEEP=1 C8S_IT_SETUP_ONLY=1`); mocked attestation, node shell via `docker exec`; the mock signs nothing and verifies only at the mock, so `evidence_unsigned` and `relying_party` answer 77 | `C8S_IT_WORKDIR` |
| [`metal.sh`](backends/metal.sh) | the attested node image a metal lane booted (`snp-metal-e2e`, `tdx-metal-e2e`), from its `extra-suite` hook; no node shell and no TEE on the harness host, so `image_alias`, `node_containers`, `plugin_stop`, `plugin_start`, `cds_restart`, `cds_restart_with`, `attestation_service_stop`, `private_keys`, `attest_direct`, `pod_sandbox_id`, `evidence` over a chosen launch digest and a plain-HTTP `cds_read` answer 77; `image_entrypoint` answers 77 without `crane`, `write_token` without Go; `pod_cert_file` reads through the pod's first container, so only once it runs; `node_refuses` answers yes at once, so `cds_block` returns before kube-proxy has reprogrammed the node; no external address and no mock, so `external_endpoint`, `attestation_endpoint` and `dialer_image` answer 77 | `KUBECONFIG`, `C8S_ALLOWLIST_URL`, `C8S_OPERATOR_KEY`, the `c8s` CLI on `PATH`; `go` and `crane` for the write-token and entrypoint functions |

The backends source the kind harness's `lib.sh`, render pods with
`pod-fixture.py`, and name components (the NRI DaemonSet, its socket) that
change with c8s. The tools under [`tools/`](tools) are built into images by the backends and
may import c8s packages: they stand in for peers the cluster does not have,
not for the steps' judgement. A change to any of those updates the backend in
the same PR.
`shellcheck` runs over them and `run.sh` in the node-guest-image lint workflow.

## What is a coordinated change

The suite calls `run.sh` and the backends by name. Renaming a backend
function, changing its arguments or output, or changing the variables `run.sh`
and `TestFeatures` read is a coordinated change with the suite's judge
configuration. Adding a step or a backend function is not.

Nothing here runs a scenario in this repo's CI: `make test` compiles the steps
and `TestFeatures` skips. The suite's own CI runs the steps on kind and on both
metal lanes.
