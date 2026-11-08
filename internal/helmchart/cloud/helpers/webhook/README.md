# Webhook scope helpers

Source: [templates/_webhook.tpl](../../templates/_webhook.tpl).
[All helpers](../README.md).

`c8s.webhookExcludedNamespaces` renders the namespace selector shared by the
injection webhook and the admission policies that mirror its scope. Keep those
consumers on this helper so the release namespace, Kubernetes system namespaces,
and `webhook.extraExcluded` receive consistent treatment.
