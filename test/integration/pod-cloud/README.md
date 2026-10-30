# Cloud Pod acceptance compatibility

New runs from the current `c8s-launch/v2` source are blocked before local setup or
Cloud access. This lane's bootstrap and catalog checks describe the historical
v1 pair: a Pod guest and a node-role CDS using the same image. A dedicated measured
CDS now serves port 8443, binds its raw configuration through `opkeydata/pubkey`,
and has no node-status endpoint.

Cloud main [`e829d754`](https://github.com/confidential-dot-ai/cloud/commit/e829d7549d3088852460ed99fb58b8bf8c2b62b5)
still requires [`trust.launchKey` to be a PEM public key](https://github.com/confidential-dot-ai/cloud/blob/e829d7549d3088852460ed99fb58b8bf8c2b62b5/internal/api/create.go#L1060),
including when `initData` is omitted. Its [launch contracts](https://github.com/confidential-dot-ai/cloud/blob/e829d7549d3088852460ed99fb58b8bf8c2b62b5/operator/internal/launch/launch.go#L153)
do not yet support raw measured CDS configuration. Resuming new runs requires a
Cloud API/operator release, separately admitted Pod/CDS images, and a harness
migration to explicit CDS address, independent image/launch-file pins, and CDS
port 8443. Catalog changes alone cannot enable this path.

Historical v1 acceptance receipts remain evidence for their recorded source and
image pins. They do not validate the merged v2 source. To clean an existing run,
retain its private state and use `run.sh cleanup /absolute/existing-private-state`.
Cleanup reuses the original `provider.test` and its ownership ledger; it does not
rebuild or require the current launch parser. Missing optional local interruption
proof never authorizes deletion: exact owned Cloud receipts remain required.
