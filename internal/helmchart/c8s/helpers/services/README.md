# Service and attestation helpers

Source: [templates/_services.tpl](../../templates/_services.tpl).
[All helpers](../README.md).

`c8s.attestationApiSocketPresent` is the one predicate for "a node-local
attestation socket exists": non-empty when `attestationApi.enabled` or
`node.baked` is set. The helpers below branch on it.

`c8s.attestationApiURL` selects the node-local
`unix://<runtimeDir>/attestation-api.sock` endpoint when
`attestationApi.enabled=true` or `node.baked=true`.

The chart-managed attestation API binds pod loopback. Its attest-proxy exposes
the node-local socket in `nriImagePolicy.hostPaths.runtimeDir`.
The socket helpers expose its host directory read-only. Baked nodes require a
pre-existing `Directory`; ordinary chart installs use `DirectoryOrCreate`.
The webhook rebases the socket path for injected
get-cert sidecars, and nri-image-policy NRI-mounts the directory read-only into
those sidecars.

`c8s.attestationApiConfig` takes a dict with `root` and renders the API's TOML.

With `node.baked=true`, the attester and proxy run as systemd services; CDS,
router, mesh and operator use the same Kubernetes templates as ordinary installs.
CDS and router are singleton workloads on the signed server's control-plane node.
Pod clients use the CDS Service URL; the host NRI client uses its signed endpoint.

`c8s.nodeConfigVolume` and `c8s.nodeConfigMount` expose only the nonsecret verified
launch files in `/run/c8s-node`, read-only. CDS and mesh verify peers with
`peers.json`; every CDS client uses the separate server-only `cds.json` policy.
CDS also consumes the merged seed and operator public key. Router certificate
issuance and CDS SAN authorization read `tls-san`; nginx uses its sole default
virtual host. The token-bearing launch directory is never mounted into pods.
Missing policy files fail startup. Workload sidecars retain NRI socket injection.
Cluster administrators remain trusted to manage the rendered Kubernetes objects.

`c8s.routerMeshNamespace` is the namespace whose pods serve the router's own
ports (`c8s-router`). The chart renders that Namespace under the fixed name the
enforcer compiles in (`pkg/workloadclaims.RouterNamespace`).

`c8s.cdsURL` builds the in-cluster CDS Service URL.
`c8s.nriCDSURL` uses `nriImagePolicy.cds.url` when supplied, otherwise
`https://127.0.0.1:<cds.service.nodePort>` for the host plugin.

`c8s.router.resolver` honors `router.nginx.resolver`. Otherwise `nriImagePolicy.distro=rke2`
selects `rke2-coredns-rke2-coredns.kube-system.svc.cluster.local`;
the default is `kube-dns.kube-system.svc.cluster.local`. Nginx must resolve this
name at startup.
