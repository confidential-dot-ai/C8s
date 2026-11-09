# Node placement helpers

Source: [templates/_nodes.tpl](../../templates/_nodes.tpl).
[All helpers](../README.md).

`c8s.confidentialNodeLabels` renders `confidentialNodeSelector`, the labels
this platform puts on a confidential node, as the `nodeSelector` of every pod
that must run inside a node's TEE: the nri-image-policy installer, the
attestation API, volumed and the router. The stock values file
`values-<platform>.yaml` sets the labels.

A label places a pod; it grants nothing. Evidence still comes from the node's
TEE devices, so an agent on a plain node carrying the label fails to attest.

`c8s.criticalPriorityClass` is the priority class of the node agents.
`templates/critical-pods-quota.yaml` renders the release namespace's
ResourceQuota from the same helper.
