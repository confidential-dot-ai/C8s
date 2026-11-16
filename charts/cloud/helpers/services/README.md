# Service and attestation helpers

Source: [templates/_services.tpl](../../templates/_services.tpl).
[All helpers](../README.md).

The chart-managed attestation API binds pod loopback. Its attest-proxy serves
it on `unix:///run/nri-image-policy/attestation-api.sock`
(`c8s.attestationApiURL`), in the runtime directory the admission inventory
shares. The socket helpers mount that host directory read-only. The webhook
rebases the socket path for injected get-cert sidecars, and nri-image-policy
NRI-mounts the directory read-only into those sidecars.

The proxy's health port, which kubelet probes, is
`c8s.attestProxyHealthPort`. It serves the proxy's liveness (`/livez`), its
readiness over the socket (`/healthz`) and the API's liveness
(`/upstream/livez`). `c8s.attestationApiConfig` renders the API's
TOML.

The host plugin and the clients it injects reach the CDS by the address the
installer copies to the node from the `-measurements` ConfigMap, beside the pin
it holds it to (`cds.address`, `cds.measurementsConfig`).
