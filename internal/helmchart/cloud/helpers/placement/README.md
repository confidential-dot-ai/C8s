# Host daemon placement

Source: [templates/_placement.tpl](../../templates/_placement.tpl).
[All helpers](../README.md).

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
