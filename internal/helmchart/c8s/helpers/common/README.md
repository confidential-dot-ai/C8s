# Common helpers

Source: [templates/_helpers.tpl](../../templates/_helpers.tpl).
[All helpers](../README.md).

Resource names derive from `.Release.Name`, truncate to 63 characters, and trim
trailing hyphens. `c8s.commonLabels` provides the shared chart labels.

`c8s.int` renders integer values through `int64`, avoiding scientific notation
for numeric values loaded from a values file. `c8s.positiveInt` takes a dict with
`value` and `label`, requires a positive decimal integer, and uses the label in
its validation error.

`c8s.hostDaemonAffinity` takes an affinity map and returns a copy that excludes
nodes labelled `confidential.ai/pod-cvm=true`. It adds a required `NotIn ["true"]`
expression to every existing nonempty node-selector term, preserving their OR
relationship, match fields, preferred affinity, and pod affinity. Without a
required selector, it creates one exclusion term. Explicit empty required
selectors and empty terms retain Kubernetes' no-match behavior. The input is
never mutated, so repeated callers see the same constraints.

`c8s.nriHostDaemonAffinity` takes the chart root and combines the installer's
Linux requirement and `nriImagePolicy.nodeAffinity.excludeLabels` with that
exclusion. Both the installer and its uninstall hook use it. The attestation
API, volumed, and volumed teardown PodSpec helpers use `c8s.hostDaemonAffinity`
directly. The exclusion applies even when this release's provider is disabled;
another release can own a virtual node in the same cluster.

`c8s.webhookExcludedNamespaces` renders the namespace selector shared by the
injection webhook and the admission policies that mirror its scope. Keep those
consumers on this helper so the release namespace, Kubernetes system namespaces,
and `webhook.extraExcluded` receive consistent treatment.
