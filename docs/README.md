# C8s docs

C8s is confidential Kubernetes. Each node is a confidential VM on AMD SEV-SNP
or Intel TDX, so a workload's memory stays encrypted while it runs, what booted
is measured, and a client outside the cluster can check that measurement on the
connection it uses before it sends anything. These pages are the short, current
description of how the parts fit together. The full manual is at
<https://confidential.ai/docs/c8s>.

## Where to start

- Platform operator: [overview.md](overview.md),
  [QUICKSTART.md](QUICKSTART.md), [operator.md](operator.md),
  [allowlist-and-capabilities.md](allowlist-and-capabilities.md),
  [upgrade.md](upgrade.md).
- Workload owner: [overview.md](overview.md), [DEMO.md](DEMO.md),
  [workloads.md](workloads.md), [allowlist-entries.md](allowlist-entries.md),
  [secrets.md](secrets.md), [volumes.md](volumes.md).
- Verifier: [overview.md](overview.md), [armtls.md](armtls.md),
  [verify.md](verify.md), [routes-evidence.md](routes-evidence.md),
  [releases.md](releases.md).
- Contributor: [overview.md](overview.md), [glossary.md](glossary.md),
  [engineering-standards.md](engineering-standards.md),
  [integration-tests.md](integration-tests.md).

## Pages

| Page | Kind | Covers |
|---|---|---|
| [QUICKSTART.md](QUICKSTART.md) | tutorial | Install C8s on a cluster and confirm it works |
| [DEMO.md](DEMO.md) | tutorial | Deploy the sample workload and inspect what was injected |
| [workloads.md](workloads.md) | how-to | Onboard your own workload |
| [verify.md](verify.md) | how-to | Verify a deployment from outside |
| [upgrade.md](upgrade.md) | how-to | Upgrade a cluster to a new release |
| [integration-tests.md](integration-tests.md) | how-to | Run the test harnesses |
| [glossary.md](glossary.md) | reference | The canonical name of each concept |
| [allowlist-entries.md](allowlist-entries.md) | reference | Workload entry format and the `c8s allowlist` commands |
| [releases.md](releases.md) | reference | Versioning, published artifacts, release verification |
| [operator.md](operator.md) | reference | Running a cluster: install, CDS, router, credentials |
| [overview.md](overview.md) | explanation | Trust boundary, components, the life of a confidential pod |
| [allowlist-and-capabilities.md](allowlist-and-capabilities.md) | explanation | What may run, and why |
| [armtls.md](armtls.md) | explanation | Attested identity and the handshake |
| [getcert-workload-binding.md](getcert-workload-binding.md) | explanation | How a certificate binds to one pod run |
| [secrets.md](secrets.md) | explanation | Secret release |
| [volumes.md](volumes.md) | explanation | Encrypted volumes |
| [routes-evidence.md](routes-evidence.md) | explanation | Proving which routes the router serves |
| [node-exec-mode.md](node-exec-mode.md) | explanation | Why exec into a container is refused |
| [engineering-standards.md](engineering-standards.md) | policy | Engineering standards for this repository |
