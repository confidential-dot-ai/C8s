# Shared chart template helpers

Named templates are grouped by responsibility. Callers use their existing
`include` names; Helm loads every underscore-prefixed template file of this
library chart into the chart that depends on it. Each reference below documents
one template file and links back to it.

| Reference | Template file | Responsibility |
| --- | --- | --- |
| [Allowlist](allowlist/README.md) | [_allowlist.tpl](../templates/_allowlist.tpl) | Component inventory, local admission list, CDS seed |
| [Certificates](certificates/README.md) | [_certificates.tpl](../templates/_certificates.tpl) | Certificate sidecars, security context, DNS SAN pattern |
| [Common](common/README.md) | [_names.tpl](../templates/_names.tpl), [_ints.tpl](../templates/_ints.tpl), [_identities.tpl](../templates/_identities.tpl), [_podcvm.tpl](../templates/_podcvm.tpl) | Resource names, labels, integers, reserved identities, the Pod CVM provider's grants |
| [Component table](components/README.md) | [_components.tpl](../templates/_components.tpl) | The component images and the router's nginx pin |
| [Images](images/README.md) | [_images.tpl](../templates/_images.tpl) | Image references and pull secrets |
| [Mesh endpoint](mesh/README.md) | [_mesh.tpl](../templates/_mesh.tpl) | The member pod's mesh endpoint and its probes |
| [Router](router/README.md) | [_router.tpl](../templates/_router.tpl) | The router's nginx files, ports and containers |

Keep purpose and invariant comments beside the template; keep longer contracts
and cross-template coordination notes in these references. Documentation lives
outside `templates/` so Helm does not render it as a Kubernetes resource.
