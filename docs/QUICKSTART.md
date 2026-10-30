# Install C8s

Install C8s on a Kubernetes cluster and confirm it runs.

The cluster's trust root arrives before it: CDS, the Certificate Distribution
Service, runs in its own confidential VM outside the cluster, holds the
allowlist — the operator-signed list of what may run — and signs each
workload's certificate. The install names it, and brings the `c8s operator`,
the controller and admission webhooks that give every pod its identity. Terms
used once and not explained here are in [glossary.md](glossary.md).

This tutorial uses one deployment shape, `--cvm-mode=bare-metal`: every node
boots the measured C8s node image, so the node is itself the confidential VM —
a VM whose memory the CPU encrypts and whose boot state the hardware measures.
[overview.md](overview.md) has the other modes.

## Prerequisites

- A Kubernetes cluster whose nodes boot a measured C8s node image, and
  platform-admin credentials for it.
- The `c8s` CLI of the version you intend to run, from its release artifact or
  `make install` in a source checkout. Its build version is the default
  `--image-tag`, so the CLI picks which component images the install pins; an
  unstamped build falls back to the `main` tag ([releases.md](releases.md)).
- `helm`, `kubectl`, and `crane` on PATH. `crane` resolves the component image
  tags to digests; it is needed unless you pass `--resolve-digests=false`.
- A running CDS: the address its VM answers on, and the `cds-pin.json` that
  `c8s cds config new` wrote beside the configuration it boots
  ([operator.md](operator.md#what-an-install-deploys)).
- Host port 443 free on the nodes: the router, the cluster's public entry
  point, publishes the front door there, and install refuses when every node
  has it bound.
- Node kernels from Linux 6.5, which the node's admission inventory needs to
  pin the process on the other end of its socket. SEV-SNP and TDX hosts need
  newer kernels than that, so a supported node already satisfies it.

If the cluster's own node image already deploys C8s, its `c8s-system` namespace
carries the label `confidential.ai/baked=true` and `c8s install` refuses: that
image owns the core services, and you configure them through its signed launch
configuration instead ([operator.md](operator.md)).

## 1. Generate an operator keypair

The private key signs every allowlist, secret, volume, and route write. CDS
pins the public half at install time and accepts writes signed by nothing else.

```sh
c8s keys new --out c8s-operator.key --pub-out c8s-operator-pub.pem
```

```text
wrote c8s-operator.key (private, 0600) and c8s-operator-pub.pem (public)
```

Keep `c8s-operator.key`. Without it you cannot change cluster policy; with it,
anyone can.

## 2. Install

Two flags are required, and they are independent. `--cvm-mode` is the
deployment shape (`bare-metal` here). `--hardware-platform` names the CPU TEE
the nodes run: `sev-snp` for AMD SEV-SNP, `tdx` for Intel TDX.

```sh
c8s install --namespace c8s-system --cvm-mode=bare-metal --hardware-platform=sev-snp \
  --operator-keys c8s-operator-pub.pem \
  --cds-address 10.0.0.9:8443 --cds-pin cds-pin.json
```

Replace both values with your own CDS: the address its VM answers on, and the
`cds-pin.json` `c8s cds config new` wrote beside its configuration. Every
client of this cluster dials that address and holds the CDS to that pin, and
the chart refuses to render without both.

Under `bare-metal` the node image already runs `attestation-api` and the
admission plugin — the container-runtime plugin that admits or denies every
container — so the chart adds the operator and its webhooks, the router, and
the `c8s-nri-image-policy-worker` DaemonSet, which carries the CDS this
release names to the baked plugin.

What the flags above do, with the semantics in
[operator.md](operator.md#what-an-install-deploys):

- `--operator-keys`: pins the public keys CDS accepts writes from; the install
  refuses without it, unless a `-f` file sets `cds.operatorKeys`.
- `--force`: installs regardless, with allowlist writes disabled and no route
  manifest, so cluster policy cannot change and the router answers 503.
- `--resolve-digests`: on by default, resolving each component image tag to its
  registry digest and pinning it, because the admission plugin admits C8s
  components by digest. Pass `--resolve-digests=false` with a `-f values.yaml`
  to supply the digests yourself.
- `--wait`: on by default, so the command returns once the release is ready.

## 3. Confirm the platform pods

```sh
kubectl -n c8s-system wait --for=condition=Ready pod --all --timeout=5m
```

```text
pod/c8s-operator-... condition met
```

Every line ends `condition met`. The namespace holds the operator and the
`c8s-nri-image-policy-worker` DaemonSet.

## 4. Confirm the router

```sh
kubectl -n c8s-router wait --for=condition=Ready pod --all --timeout=5m
```

The router runs in its own namespace, `c8s-router`. It answers 503 to
application requests until a route manifest — the operator-signed list of
hosts, paths, and backends it serves — is stored
([operator.md](operator.md#route-manifest)), so an empty front door at this
point is expected.

## Next steps

- Deploy the sample workload and see what the webhook injects:
  [DEMO.md](DEMO.md).
- Onboard your own workload, secrets, volumes, and routes:
  [workloads.md](workloads.md).
- Check from outside that CDS is a genuine TEE running the code you pinned:
  [verify.md](verify.md).
- Chart options, credentials, and day-2 operations: [operator.md](operator.md).

To remove C8s again, uninstall the release; it also sweeps the artifacts the
release left on each node ([operator.md](operator.md)):

```sh
c8s uninstall --namespace c8s-system
```
