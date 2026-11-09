# Cloud chart template helpers

Named templates are grouped by responsibility. Callers use their existing
`include` names; Helm loads every `.tpl` file in this chart. Shared helpers
live in [the c8s-lib chart](../../lib/helpers/README.md).

| Reference | Template file | Responsibility |
| --- | --- | --- |
| [CDS pin and address](cds/README.md) | [_cds.tpl](../templates/_cds.tpl) | Validated CDS pin document and endpoint address |
| [Component shapes](../../lib/helpers/allowlist/README.md#component-shapes) | [_components.tpl](../templates/_components.tpl) | The component workloads this release runs |
| [NRI image policy](nri-image-policy/README.md) | [nri-image-policy-helpers.tpl](../templates/nri-image-policy-helpers.tpl), [nri-image-policy-install-script.tpl](../templates/nri-image-policy-install-script.tpl) | The installer DaemonSet's paths and the scripts it runs |
| [Placement](placement/README.md) | [_placement.tpl](../templates/_placement.tpl) | Host daemons kept off Pod CVM virtual nodes |
| [Router](router/README.md) | [router-helpers.tpl](../templates/router-helpers.tpl) | The cloud front door's identity, nginx files and ports |
| [Services](services/README.md) | [_services.tpl](../templates/_services.tpl) | Attestation endpoints, socket access, node launch files |

Keep purpose and invariant comments beside the template; keep longer contracts
and cross-template coordination notes in these references. Documentation lives
outside `templates/` so Helm does not render it as a Kubernetes resource.
