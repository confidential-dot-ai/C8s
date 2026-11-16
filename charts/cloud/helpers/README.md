# Cloud chart template helpers

Named templates are grouped by responsibility. Callers use their existing
`include` names; Helm loads every `.tpl` file in this chart. Shared helpers
live in [the c8s-lib chart](../../lib/helpers/README.md).

| Reference | Template file | Responsibility |
| --- | --- | --- |
| [CDS pin and address](cds/README.md) | [_cds.tpl](../templates/_cds.tpl) | Validated CDS pin document and endpoint address |
| [Component shapes](../../lib/helpers/allowlist/README.md#component-shapes) | [_components.tpl](../templates/_components.tpl) | The component workloads this release runs |
| [NRI image policy](nri-image-policy/README.md) | [nri-image-policy-helpers.tpl](../templates/nri-image-policy-helpers.tpl), [nri-image-policy-install-script.tpl](../templates/nri-image-policy-install-script.tpl) | The installer DaemonSet's paths and the scripts it runs |
| [Node placement](nodes/README.md) | [_nodes.tpl](../templates/_nodes.tpl) | The confidential nodes the agents and the router run on |
| [Placement](placement/README.md) | [_placement.tpl](../templates/_placement.tpl) | Host daemons kept off Pod CVM virtual nodes |
| [Router](router/README.md) | [router-helpers.tpl](../templates/router-helpers.tpl) | The cloud front door's identity, nginx files and ports |
| [Services](services/README.md) | [_services.tpl](../templates/_services.tpl) | Attestation endpoint and socket access |
| Webhook exclusions | [_webhook.tpl](../templates/_webhook.tpl) | Provider and explicit namespace exclusions |

`c8s.cloudAdditionalExcludedNamespaces` returns the deduplicated union of
`controlPlane.webhook.extraExcluded` and `nriImagePolicy.policy.exemptNamespaces`.
Both the operator's sweep arguments and [`webhooks.yaml`](../templates/webhooks.yaml)
use it. The latter renders the [control-plane definitions](../../control-plane/helpers/README.md)
with a copied subchart context. The cloud schema requires
`controlPlane.webhook.render: false` so each webhook configuration renders once.

Keep purpose and invariant comments beside the template; keep longer contracts
and cross-template coordination notes in these references. Documentation lives
outside `templates/` so Helm does not render it as a Kubernetes resource.
