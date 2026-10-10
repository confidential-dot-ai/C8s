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
cluster. A new sentence is a new step here; a scenario reusing existing
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
"nginx" means, what the CDS serves, whether the policy enforcer on a node is
enforcing and how often it pulls, whether the node's base allowlist names a
digest, which containers a node's runtime holds for a digest, and a
Restricted-compatible pod manifest to deploy. It also acts for the operator: a
scenario's allowlist entries are written and deleted through the backend's
signed path, and undone after the scenario. The enforcer exposes nothing about
the allowlist version it holds, so after a write the steps wait out two pull
intervals before acting on it.

[`backends/common.sh`](backends/common.sh) states the interface: every
function, its arguments, what it prints, and the exit status that means "this
environment cannot express that", which the steps turn into a skip. It also
implements the functions that are the same everywhere. A backend sources it,
sets `PLATFORM`, defines what differs, and ends with `dispatch "$@"`, which
rejects unknown names.

| Backend | Environment | Requires |
|---|---|---|
| [`kind.sh`](backends/kind.sh) | the kept kind cluster of [`test/integration/cluster/run.sh`](../integration/cluster/run.sh) (`C8S_IT_KEEP=1 C8S_IT_SETUP_ONLY=1`); mocked attestation, node shell via `docker exec` | `C8S_IT_WORKDIR` |
| [`metal.sh`](backends/metal.sh) | the attested node image a metal lane booted (`snp-metal-e2e`, `tdx-metal-e2e`), from its `extra-suite` hook; no node shell, so `image_alias` and `node_containers` answer 77 | `KUBECONFIG`, `C8S_ALLOWLIST_URL`, `C8S_OPERATOR_KEY`, the `c8s` CLI on `PATH` |

The backends source the kind harness's `lib.sh`, render pods with
`pod-fixture.py`, and name components (the NRI DaemonSet, its socket) that
change with c8s. A change to any of those updates the backend in the same PR.
`shellcheck` runs over them and `run.sh` in the node-guest-image lint workflow.

## What is a coordinated change

The suite calls `run.sh` and the backends by name. Renaming a backend
function, changing its arguments or output, or changing the variables `run.sh`
and `TestFeatures` read is a coordinated change with the suite's judge
configuration. Adding a step or a backend function is not.

Nothing here runs a scenario in this repo's CI: `make test` compiles the steps
and `TestFeatures` skips. The suite's own CI runs the steps on kind and on both
metal lanes.
