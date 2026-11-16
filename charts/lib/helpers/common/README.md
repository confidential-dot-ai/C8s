# Common helpers

Sources: [_names.tpl](../../templates/_names.tpl),
[_identities.tpl](../../templates/_identities.tpl),
[_podcvm.tpl](../../templates/_podcvm.tpl).
[All helpers](../README.md).

Resource names derive from `.Release.Name`, truncate to 63 characters, and trim
trailing hyphens. `c8s.commonLabels` provides the shared chart labels.

`c8s.webhookServicePort` is the operator Service port the API server dials the
admission webhooks on; the Service and both webhook configurations include it.

`c8s.routerMeshNamespace` is the namespace whose pods serve the router's own
ports (`c8s-router`), the fixed name the enforcer compiles in
(`pkg/workloadclaims.RouterNamespace`).

`c8s.podCVMProviderGrants` takes a dict with `root` and `subject` and renders
what the operator's Pod CVM provider needs, bound to that subject: a ClusterRole
for pods, pods/status, nodes and events.k8s.io Events, and a Role for Secrets
in the release namespace alone, where the provider keeps its records. The c8s
chart binds it to the operator's ServiceAccount, the c8s-worker chart to the
user `c8s-operator`.
