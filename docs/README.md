# C8s docs

C8s is confidential Kubernetes. Each node is a confidential VM on AMD SEV-SNP
or Intel TDX, so a workload's memory stays encrypted while it runs, what booted
is measured, and a client outside the cluster can check that measurement on the
connection it uses before it sends any application data. The full manual is at
<https://confidential.ai/docs/c8s>.

## Where to start

Everyone: [overview.md](overview.md), then [guarantees.md](guarantees.md).

- Platform operator: [operator.md](operator.md),
  [allowlist-and-capabilities.md](allowlist-and-capabilities.md),
  [cloud-cds.md](cloud-cds.md), [upgrade.md](upgrade.md).
- Workload owner: [DEMO.md](DEMO.md), [workloads.md](workloads.md),
  [allowlist-entries.md](allowlist-entries.md), [secrets.md](secrets.md),
  [volumes.md](volumes.md).
- Verifier: [verify.md](verify.md), [measurements.md](measurements.md),
  [security-model.md](security-model.md).
- Contributor: [glossary.md](glossary.md),
  [engineering-standards.md](engineering-standards.md),
  [review-guide.md](review-guide.md),
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
| [pod-secrets.md](pod-secrets.md) | reference | Pod CVM secret release brokered to a KMS, and the CDS-to-KMS wire |
| [volumes.md](volumes.md) | explanation | Encrypted volumes |
| [workloads.md](workloads.md) | how-to | Onboard your own workload |
| [DEMO.md](DEMO.md) | tutorial | Deploy the sample workload and inspect what was injected |
| **Ingress and routing** | | |
| [routes-evidence.md](routes-evidence.md) | explanation | Proving which routes the router serves |
| **Operating a cluster** | | |
| [operator.md](operator.md) | explanation | Running a cluster: install, the Certificate Distribution Service, the router |
| [cloud-cds.md](cloud-cds.md) | how-to | Where a cloud cluster's CDS runs, the flows it needs, node pins on AKS and GKE |
| [launch-configuration.md](launch-configuration.md) | reference | The launch document a measured worker boots with |
| [pod-cvm-provider.md](pod-cvm-provider.md) | reference | Scheduling annotated Pods as Cloud Pod CVMs |
| [upgrade.md](upgrade.md) | how-to | Upgrade a cluster to a new release |
| **Verifying a deployment** | | |
| [verify.md](verify.md) | how-to | Verify a deployment from outside |
| [measurements.md](measurements.md) | reference | What each platform measures, and the measurements config |
| [releases.md](releases.md) | reference | Versioning, published artifacts, release verification |
| [../SECURITY.md](../SECURITY.md) | policy | Reporting a vulnerability |
| **Contributing** | | |
| [engineering-standards.md](engineering-standards.md) | policy | Engineering standards for this repository |
| [review-guide.md](review-guide.md) | how-to | Review correctness, security and supporting evidence |
| [integration-tests.md](integration-tests.md) | how-to | Run the test harnesses |
