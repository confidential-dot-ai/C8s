# Mesh endpoint helpers

Source: [templates/_mesh.tpl](../../templates/_mesh.tpl).
[All helpers](../README.md).

`c8s.meshEndpointContainer` renders the pod mesh endpoint: the native sidecar
that carries a member pod's captured TCP over armTLS. The admission webhook
builds the same container for tenant pods
(`internal/webhook/pod_mutator.go "meshContainer"`), so a chart-rendered member
pod — the router — holds one endpoint shape with it.

The node's measured base allowlist grants the mesh role to that argv, those
mounts and that reserved UID alone
(`node-guest-image/c8s/image-policy.yaml.in`), so the credential paths are
fixed: `c8s.certDir`, `c8s.certFile`, `c8s.keyFile` and `c8s.caFile` in [_helpers.tpl](../../templates/_helpers.tpl) are what both
the endpoint and the pod's get-cert containers use. A pod reading or publishing
elsewhere takes no role, and the enforcer refuses it.

The helper takes the chart root. The pod must declare the `c8s-certs` volume
the endpoint mounts, and the endpoint must come first in `initContainers`: the
enforcer gates the rest of the pod on its start.

The endpoint's startup and readiness probes are HTTP on its health port, with
every field set, so a stored pod still matches what was rendered. Never
`exec`: a locked node image denies every runc exec.
