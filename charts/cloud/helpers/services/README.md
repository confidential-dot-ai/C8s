# Service and attestation helpers

Source: [templates/_services.tpl](../../templates/_services.tpl).
[All helpers](../README.md).

The chart-managed attestation API binds
`unix:///run/nri-image-policy/attestation-api.sock` (`c8s.attestationApiURL`)
itself, in the runtime directory the admission inventory shares, and no TCP
port. The socket's group is `c8s.nodeSocketGID`. The socket helpers mount that
host directory read-only. The webhook
rebases the socket path for injected get-cert sidecars, and nri-image-policy
NRI-mounts the directory read-only into those sidecars.

Kubelet cannot probe a Unix socket, so the pod's `probes` sidecar
(`c8s attest-proxy probes`) serves the probes on `c8s.attestationApiProbePort`:
its own liveness (`/livez`), readiness over the socket (`/healthz`) and the
API's liveness (`/api/livez`). `c8s.attestationApiConfig` renders the API's
TOML.

The host plugin and the clients it injects reach the Trust Authority by the address the
installer copies to the node from the `-measurements` ConfigMap, beside the pin
it holds it to (`ta.address`, `ta.measurementsConfig`).
