# Conformance backends

A backend answers a fixed set of questions about one running c8s environment
so that an external test suite can observe the cluster without knowing how it
was built: which Kubernetes node stands behind a scenario's "node one", which
pullable reference and digest a scenario's "nginx" means, what the CDS serves,
whether the policy enforcer on a node is enforcing, which containers a node's
runtime holds for a digest, and a Restricted-compatible pod manifest to deploy.

The consumer is an external conformance suite, maintained outside this repo:
its step definitions call `backends/<name>.sh <function> <args...>` once per
question, read stdout,
and treat exit 77 as "this environment cannot express that" (a named skip).
Any other failure is a broken harness.

[`backends/common.sh`](backends/common.sh) states the interface: every
function, its arguments, what it prints, and which answers are fixed for a
run. It also implements the functions that are the same everywhere. A backend
sources it, sets `PLATFORM`, defines what differs, and ends with
`dispatch "$@"`, which rejects unknown function names.

| Backend | Environment | Requires |
|---|---|---|
| [`kind.sh`](backends/kind.sh) | the kept kind cluster of [`test/integration/cluster/run.sh`](../integration/cluster/run.sh) (`C8S_IT_KEEP=1 C8S_IT_SETUP_ONLY=1`); mocked attestation, node shell via `docker exec` | `C8S_IT_WORKDIR` |
| [`metal.sh`](backends/metal.sh) | the attested node image a metal lane booted (`snp-metal-e2e`, `tdx-metal-e2e`), from its `extra-suite` hook; no node shell, so `image_alias` and `node_containers` answer 77 | `KUBECONFIG`, `C8S_ALLOWLIST_URL`, `C8S_OPERATOR_KEY`, the `c8s` CLI on `PATH` |

The backends live here, not with the suite, because they are harness code: they
source the kind harness's `lib.sh`, render pods with `pod-fixture.py`, and name
components (the NRI DaemonSet, its socket) that change with c8s. A change to any
of those updates the backend in the same PR.

Renaming a function, changing its arguments or its output is a coordinated
change: the suite's step definitions call these by name. Adding a function is
not; the suite skips what it does not know.

`shellcheck` runs over these scripts in the node-guest-image lint workflow.
There is no automated exercise of them in this repo; the suite's own CI runs
them against all three environments.
