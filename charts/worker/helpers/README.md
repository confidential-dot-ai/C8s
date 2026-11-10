# Worker chart template helpers

Named templates are grouped by responsibility. Callers use their existing
`include` names; Helm loads every `.tpl` file in this chart. Shared helpers
live in [the c8s-lib chart](../../lib/helpers/README.md).

| Template file | Responsibility |
| --- | --- |
| [_allowlist.tpl](../templates/_allowlist.tpl) | The component workloads this chart runs and the seed its CDS serves |
| [_node.tpl](../templates/_node.tpl) | The node directories, the attestation-api URL and the inventory socket group |
| [cluster/_router.tpl](../templates/cluster/_router.tpl) | The worker front door's pod spec, its ACME sidecar, argv and mounts |

The router requires `confidential.ai/router-eligible=true`. Each worker publishes
this label after matching fresh evidence against the CDS node policy. An explicit
mismatch removes eligibility and releases an unready router whose certificate
wait gate is running. Transient check failures retain the last known decision.

Keep purpose and invariant comments beside the template; keep longer contracts
and cross-template coordination notes here. Documentation lives outside
`templates/` so Helm does not render it as a Kubernetes resource.
