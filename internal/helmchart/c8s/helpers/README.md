# Chart template helpers

Named templates are grouped by responsibility. Callers use their existing
`include` names; Helm loads every underscore-prefixed template file in this chart.
Each file links to its reference below, and each reference links back to the file.

| Reference | Template file | Responsibility |
| --- | --- | --- |
| [Common](common/README.md) | [_helpers.tpl](../templates/_helpers.tpl) | Resource names, labels, integers, webhook namespace scope |
| [Images](images/README.md) | [_images.tpl](../templates/_images.tpl) | Image references and pull secrets |
| [Services](services/README.md) | [_services.tpl](../templates/_services.tpl) | Attestation and CDS endpoints, socket access, DNS resolver |
| [Certificates](certificates/README.md) | [_certificates.tpl](../templates/_certificates.tpl) | Certificate sidecars, security context, DNS SAN pattern |
| [Mesh endpoint](mesh/README.md) | [_mesh.tpl](../templates/_mesh.tpl) | The member pod's mesh endpoint and its probes |
| [Allowlist](allowlist/README.md) | [_allowlist.tpl](../templates/_allowlist.tpl) | Component inventory, local admission list, CDS seed |

Keep purpose and invariant comments beside the template; keep longer contracts
and cross-template coordination notes in these references. Documentation lives
outside `templates/` so Helm does not render it as a Kubernetes resource.
