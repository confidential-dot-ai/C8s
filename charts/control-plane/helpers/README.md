# Webhook helpers

Source: [templates/_webhook.tpl](../templates/_webhook.tpl). Shared helpers
live in [the c8s-lib chart](../../lib/helpers/README.md).

`c8s.webhookExcludedNamespacesMatchExpression` renders the namespace selector
expression both webhook configurations share, so the release namespace, the
router's, the Kubernetes system namespaces and `webhook.extraExcluded` receive
the same treatment, with duplicate names removed.

`c8s.podInjectorWebhook` and `c8s.podValidatorWebhook`, defined in
[`webhook.yaml`](../templates/webhook.yaml) and
[`webhook-validating.yaml`](../templates/webhook-validating.yaml), render the
two configurations. `webhook.render` defaults to `true` for standalone and
dependency use. The cloud chart sets it to `false` and renders the definitions
with its [effective exclusions](../../cloud/helpers/README.md).

`c8s.webhookClientConfig` points a webhook at `webhook.url` plus its path.
`webhook.url` is `https://<host>:<port>` — the address of an operator the API
server reaches off-cluster, as a cluster of workers does. Without it the
webhook is pointed at the operator's Service in the release namespace, on the
shared `c8s.webhookServicePort`, under its own path.

`c8s.webhookAnnotationsBlock` renders the `annotations` key from
`webhook.annotations`, and nothing when that map is empty.
