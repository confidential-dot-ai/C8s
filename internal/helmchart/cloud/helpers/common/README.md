# Common helpers

Source: [templates/_helpers.tpl](../../templates/_helpers.tpl).
[All helpers](../README.md).

Resource names derive from `.Release.Name`, truncate to 63 characters, and trim
trailing hyphens. `c8s.commonLabels` provides the shared chart labels.

`c8s.int` renders integer values through `int64`, avoiding scientific notation
for numeric values loaded from a values file. `c8s.positiveInt` takes a dict with
`value` and `label`, requires a positive decimal integer, and uses the label in
its validation error.

`c8s.webhookExcludedNamespaces` renders the namespace selector shared by the
injection webhook and the admission policies that mirror its scope. Keep those
consumers on this helper so the release namespace, Kubernetes system namespaces,
and `webhook.extraExcluded` receive consistent treatment.
