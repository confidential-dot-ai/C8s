# C8s docs

C8s is confidential Kubernetes. Each node is a confidential VM on AMD SEV-SNP
or Intel TDX, so a workload's memory stays encrypted while it runs, what booted
is measured, and a client outside the cluster can check that measurement on the
connection it uses before it sends any application data. The full manual is at
<https://confidential.ai/docs/c8s>.

## Where to start

Everyone: [overview.md](overview.md), then [guarantees.md](guarantees.md).

- Platform operator: [QUICKSTART.md](QUICKSTART.md),
  [operator.md](operator.md),
  [allowlist-and-capabilities.md](allowlist-and-capabilities.md),
  [upgrade.md](upgrade.md).
- Workload owner: [DEMO.md](DEMO.md), [workloads.md](workloads.md),
  [allowlist-entries.md](allowlist-entries.md), [secrets.md](secrets.md),
  [volumes.md](volumes.md).
- Verifier: [verify.md](verify.md), [measurements.md](measurements.md),
  [security-model.md](security-model.md).
- Contributor: [glossary.md](glossary.md),
  [engineering-standards.md](engineering-standards.md),
  [integration-tests.md](integration-tests.md).

## Pages

| Page | Kind | Covers |
|---|---|---|
| **Start here** | | |
| [overview.md](overview.md) | explanation | Trust boundary, components, the life of a confidential pod |
| [guarantees.md](guarantees.md) | explanation | The six promises, what each covers, how to check it |
| [security-model.md](security-model.md) | explanation | How C8s holds up, adversary by adversary |
| [glossary.md](glossary.md) | reference | The canonical name of each concept |
| **Nodes and admission** | | |
| [allowlist-and-capabilities.md](allowlist-and-capabilities.md) | explanation | What may run on a node, and what it may hold |
| [allowlist-entries.md](allowlist-entries.md) | reference | Workload entry format and the `c8s allowlist` commands |
| [node-exec-mode.md](node-exec-mode.md) | explanation | Why exec into a container is refused |
| **Identity and the mesh** | | |
| [armtls.md](armtls.md) | explanation | Attested identity and the handshake |
| [getcert-workload-binding.md](getcert-workload-binding.md) | explanation | How a certificate binds to one pod run |
| [certificate-extensions.md](certificate-extensions.md) | reference | Every X.509 extension C8s issues, and who checks it |
| **Workload data** | | |
| [secrets.md](secrets.md) | explanation | Secret release |
| [volumes.md](volumes.md) | explanation | Encrypted volumes |
| [workloads.md](workloads.md) | how-to | Onboard your own workload |
| [DEMO.md](DEMO.md) | tutorial | Deploy the sample workload and inspect what was injected |
| **Ingress and routing** | | |
| [routes-evidence.md](routes-evidence.md) | explanation | Proving which routes the router serves |
| **Operating a cluster** | | |
| [QUICKSTART.md](QUICKSTART.md) | tutorial | Install C8s on a cluster and confirm it works |
| [operator.md](operator.md) | explanation | Running a cluster: install, the Certificate Distribution Service, the router, credentials |
| [launch-configuration.md](launch-configuration.md) | reference | The signed launch document a measured node boots with |
| [upgrade.md](upgrade.md) | how-to | Upgrade a cluster to a new release |
| **Verifying a deployment** | | |
| [verify.md](verify.md) | how-to | Verify a deployment from outside |
| [measurements.md](measurements.md) | reference | What each platform measures, and the measurements config |
| [releases.md](releases.md) | reference | Versioning, published artifacts, release verification |
| [../SECURITY.md](../SECURITY.md) | policy | Reporting a vulnerability |
| **Contributing** | | |
| [engineering-standards.md](engineering-standards.md) | policy | Engineering standards for this repository |
| [integration-tests.md](integration-tests.md) | how-to | Run the test harnesses |
