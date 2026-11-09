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

The nri-image-policy installer, the attestation API and volumed use
`c8s.hostDaemonAffinity` beside their
[confidential-node selector](../nodes/README.md). The exclusion applies even when this release's provider is disabled;
another release can own a virtual node in the same cluster.
