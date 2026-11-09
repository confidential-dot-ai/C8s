# Upgrade a cluster

Move a chart-installed C8s cluster to a new release.

Every node admits C8s's own components by image digest, and a cluster's CDS —
the VM outside the cluster that serves the allowlist — reads the workload
entries its measured configuration carries only at start. So the new release's
entries reach the nodes only if you publish them through the running CDS first,
which is why the steps are ordered this way
([allowlist-and-capabilities.md](allowlist-and-capabilities.md#bootstrap)).

## Prerequisites

- The operator private key matching the public keys in the CDS's measured
  configuration (`c8s cds config new --operator-keys`): CDS takes no write
  signed under any other key.
- The new release's `c8s` CLI, plus `helm`, `kubectl`, `crane`, `yq`, and
  `curl` on each node.
- The `-f` values file and flags you installed with: step 1 renders from them,
  and `nriImagePolicy.mesh.resolver` and `.clusterRanges` are in that file.
- Outbound HTTPS to AMD's key service on SEV-SNP: `c8s allowlist` verifies
  CDS's evidence itself, inside its 15s `--timeout`.
- A root shell on each node for steps 2 and 4. A measured node image has none.

## Flags that changed

An install from before v0.99.0 names flags this release's CLI does not take.
Steps 1 and 5 take their replacements:

| Installed with | Now |
|---|---|
| `--cvm-mode aks --hardware-platform sev-snp` | `--platform aks-snp` |
| `--cvm-mode aks --hardware-platform tdx` | `--platform aks-tdx` |
| `--cvm-mode gke --hardware-platform sev-snp` | `--platform gke-snp` |
| `--image-tag`, `--resolve-digests` | nothing |
| `--cvm-mode bare-metal` | nothing |
| nothing | `--pod-cidr <cidr>`, step 5 |

An AKS cluster on Azure CNI Overlay, the AKS default, publishes no
`spec.podCIDR` on its nodes; install refuses such a cluster unless step 5's
command names each of its pod ranges with `--pod-cidr`
([operator.md](operator.md#what-an-install-deploys)).

The `--platform` value is step 1's `<PLATFORM>`. A release CLI pins each
component to the digest the `c8s-cloud` chart of its own version stamps, so no
flag names an image; a build that is not a release renders the chart `--chart`
names ([releases.md](releases.md)). The cloud chart deploys the node services
itself, so `c8s install` installs on AKS and GKE confidential VMs alone: a
cluster of workers carries those services in its measured image
([overview.md](overview.md#cvm-modes-and-hardware-platforms)).

## 1. Render the new release's CDS seed

Render from the values the upgrade will apply, or the entries you publish are
not the ones its pods need — the same flags and `-f` file:

```sh
CDS=https://<CDS_ADDRESS>       # the CDS this cluster trusts
helm pull oci://ghcr.io/confidential-dot-ai/charts/c8s-cloud --version <X.Y.Z> --untar
helm template c8s ./c8s-cloud --namespace c8s-system --kube-version 1.31.0 \
  -f ./c8s-cloud/values-<PLATFORM>.yaml -f values.yaml \
  --set-string cds.address=<CDS_ADDRESS> --set-file cds.measurementsConfig=cds-pin.json \
  --set-file cds.operatorKeys=c8s-operator-pub.pem \
  --show-only templates/allowlist-seed.yaml |
  yq '.data["allowlist-seed.json"]' > seed.json
c8s allowlist lint seed.json
```

The lint prints `ok: no findings`. `<PLATFORM>` (`aks-snp`, `aks-tdx`,
`gke-snp`) is the chart stock file this cluster installs with, and `<X.Y.Z>`
the version without its leading `v`. The chart carries the release's image
digests. Add `--set volumed.enabled=true` if you install with `--volumes`.

## 2. Note what each node's admission plugin enforces

```sh
curl --unix-socket /run/nri-image-policy/health.sock http://localhost/healthz
```

```text
{"status":"ok","allowlist_version":41}
```

Run it on every node and keep the highest number; `not ready` and `0` both mean
no CDS document has been applied there yet, so count that node as 0. Without a
node shell, `kubectl -n c8s-system logs -l app=c8s-nri-image-policy -c install
--tail=2` prints that body and the `[http 200]` line after it, from the
installer's last run on each node; the plugin keeps pulling, so that number
can be below the version the node enforces now.

## 3. Publish the CDS seed

```sh
c8s allowlist apply seed.json --url "$CDS" --image-policy-file cds-pin.json \
  --operator-key c8s-operator.key
```

Every entry gets a diff line — `+ <name> (new)`, `~ <name>`, or
`= <name> (unchanged)` — and then an `applied <name>` line; one write replaces
the whole live entry of every name. A lint error prints on stderr and nothing is
written.

## 4. Check CDS's version, and raise it if a node is ahead

```sh
c8s allowlist list --url "$CDS" --image-policy-file cds-pin.json
```

```text
version 48: 9 workload(s)
```

A table of the entries follows. A node applies a pulled document only when its
version is above the one it applied already, so this number must beat every
number from step 2. The counter rises by one per write, whatever the number of
entries, so the `apply` in step 3 raises it by one; an `apply` that changes
nothing raises it too.

A version at or below a node's means CDS restarted since that node last pulled,
so its counter started from the seed again. Repeat step 3 until `list` passes
the highest number from step 2. A node that stays higher takes nothing until its
plugin restarts: restart containerd there, one node at a time, having published
every entry its pods need, since on that first pull the plugin kills what the
new document does not admit. A measured worker has no shell for that, so
relaunch its VM instead; it stages the new policy at boot. Repeat step 2 until
every node reports a version at or above this one.

## 5. Run the upgrade

Run the `c8s install` command you installed with, from the new release's CLI. It
runs `helm upgrade --install` and, with `--wait` on by default, returns once the
release is ready; confirm the router namespace too, with
`kubectl -n c8s-router wait --for=condition=Ready pod --all --timeout=5m`.

An upgrade that changes the router pod rolls it, and the front door is down from
the moment the old pod stops serving until the new one serves — up to 10 seconds
for the old pod to go, since one router pod holds the public port of its node,
plus a few seconds for the new pod to start.

Install reads the allowlist CDS serves and refuses when an entry step 3
publishes is not there; it warns and goes on where it cannot reach CDS. It also
refuses when the resolved policy would deny a platform pod the cluster already
runs, before touching anything; `--force` overrides that one. The previous
release's entries stay in the allowlist, so a rollback still matches them.
