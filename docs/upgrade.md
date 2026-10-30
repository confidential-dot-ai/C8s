# Upgrade a cluster

Move a chart-installed C8s cluster to a new release.

Every node admits C8s's own components by image digest, and a cluster's CDS —
the VM outside the cluster that serves the allowlist — reads the workload
entries its measured configuration carries only at start. So the new release's
entries reach the nodes only if you publish them through the running CDS first,
which is why the steps are ordered this way
([allowlist-and-capabilities.md](allowlist-and-capabilities.md#bootstrap)).

## Prerequisites

- The operator private key you installed with, and `cds.operatorKeys` already
  set: CDS takes no write without pinned keys, and adding them later is itself
  such an upgrade.
- The new release's `c8s` CLI, plus `helm`, `kubectl`, `crane`, `yq`, and
  `curl` on each node.
- The `-f` values file and flags you installed with
  ([QUICKSTART.md](QUICKSTART.md)): step 1 renders from them, and
  `nriImagePolicy.mesh.resolver` and `.clusterRanges` are in that file.
- Outbound HTTPS to AMD's key service on SEV-SNP: `c8s allowlist` verifies
  CDS's evidence itself, inside its 15s `--timeout`.
- A root shell on each node for steps 2 and 4. A measured node image has none.

## 1. Render the new release's CDS seed

Render from the values the upgrade will apply, or the entries you publish are
not the ones its pods need — the same flags and `-f` file, plus the `--distro`
`c8s install` detects for itself:

```sh
CDS=https://<CDS_ADDRESS>       # the CDS this cluster trusts
c8s render-values --cvm-mode=<CVM_MODE> --hardware-platform=<HW_PLATFORM> \
  --distro <DISTRO> --cds-address <CDS_ADDRESS> --cds-pin cds-pin.json \
  --operator-keys c8s-operator-pub.pem > computed.yaml
helm pull oci://ghcr.io/confidential-dot-ai/charts/c8s --version <X.Y.Z> --untar
helm template c8s ./c8s --namespace c8s-system -f values.yaml -f computed.yaml \
  --show-only templates/allowlist-seed.yaml |
  yq '.data["allowlist-seed.json"]' > seed.json
c8s allowlist lint seed.json
```

The lint prints `ok: no findings`. `<CVM_MODE>` (`bare-metal`, `gke`, `aks`),
`<HW_PLATFORM>` (`sev-snp`, `tdx`) and `<X.Y.Z>`, the version without its
leading `v`, are as you install; `<DISTRO>` is `k8s` or `rke2`, and its wrong
value renames the plugin's entry.

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
--tail=1` ends with the same body, from the installer's last run on each node.

## 3. Publish the CDS seed

```sh
c8s allowlist apply seed.json --url "$CDS" --image-policy-file cds-pin.json \
  --operator-key c8s-operator.key
```

Every entry gets a diff line — `+ <name> (new)`, `~ <name>`, or
`= <name> (unchanged)` — and then an `applied <name>` line, each write replacing
the whole live entry of that name. A lint error prints on stderr and nothing is
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
number from step 2. The counter rises once per entry written, so one `apply` of
the seed raises it by the number of entries in the file.

A version at or below a node's means CDS restarted since that node last pulled,
so its counter started from the seed again. Repeat step 3 until `list` passes
the highest number from step 2. A node that stays higher takes nothing until its
plugin restarts: restart containerd there (on RKE2 the active `rke2-server` or
`rke2-agent` unit), one node at a time, having published every entry its pods
need, since on that first pull the plugin kills what the new document does not
admit. Repeat step 2 until every node reports a version at or above this one.

## 5. Run the upgrade

Run the `c8s install` command you installed with, from the new release's CLI. It
runs `helm upgrade --install` and, with `--wait` on by default, returns once the
release is ready; confirm the router namespace too, with
`kubectl -n c8s-router wait --for=condition=Ready pod --all --timeout=5m`.

Install refuses when the resolved policy would deny a platform pod the cluster
already runs, before touching anything; `--force` overrides. The previous
release's entries stay in the allowlist, so a rollback still matches them.
