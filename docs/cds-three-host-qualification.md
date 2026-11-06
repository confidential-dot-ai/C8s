# Three-host CDS qualification

This opt-in fixture continues after the completed three-worker metadata test.
It places exactly three CDS guests on distinct qualified TDX compute workers,
using the production CDS service arguments and pinned production attestation
binary. Workload private keys stay in their guest. A bounded actor accepts only
fixed test phases signed by the measured operator key; the controller verifies
native TDX armTLS, including the complete image tuple and launch file, before
sending a phase. No arbitrary commands, paths, quote service or SSH are exposed.

Raft and direct current-state metadata run sequentially with the same CDS guest
budget, images and workload. The metadata arm additionally uses three dedicated
etcd members and three stateless adapters; their resources must be included in
any cost comparison. Etcd uses Raft internally. CDS's direct-state arm has no
application WAL or Raft participant. This single-cluster qualification does not
establish capacity or isolation under many concurrent tenant clusters.

The phases exercise real certificate issuance and renewal, workload secret
release, one-use operator authorization, partition refusal, majority service,
revocation and one-at-a-time image replacement. Image A and B contain the same
CDS executable with different measured image markers: this qualifies the image
admission/replacement procedure, not arbitrary mixed-release compatibility.
Raft replacements use membership admission; current-state replacements recover
after attested provisioning. The controller requires acknowledged image-policy
decrees. Rejection of an unapproved key recipient remains a separate custody
qualification. Test clients trust the two measured images from the start, so
this run does not qualify automatic client pin refresh.
Managed Kubernetes node-token enrollment is not included in the workload burst.
Checks run before and after each replacement; this does not establish continuous
availability during replacement or preservation of one workload leaf across all
three guest replacements. Phase timings include the test operations and are
individual observations, not request latency percentiles or an availability SLO.

For this availability comparison, the test operator knows a synthetic state key
provisioned over verified armTLS. Operator exclusion was tested separately in
the native custody pilots; this fixture does not qualify the combined custody
and HA service. It changes no production identity or default. Only small inline
state is exercised; no large-object durability or availability result is claimed.

Only exact owned, expiring fixture resources may be changed. Placement uses both
worker name and independently observed Node UID, with no control-plane placement
or host fault. Cleanup uses UID preconditions, ordinary termination and an
independent read-only absence audit. CI and shared production releases are not
used. Results remain pending until a complete run and cleanup audit are saved.

Image transfer uses short framed chunks to tolerate the API streaming proxy.
The receiver checks every chunk and the assembled archive; the controller then
checks the complete reconstructed disk. A retry uses a fresh path, and all
transfer files stay on the owned disposable volume. An upload timeout never
counts as completion or a backend availability result.

The guest subnet has no general outbound NAT; ordinary Cloud API instances get
explicit egress mappings. These SDK fixtures use a dedicated, disposable
`cds-three-host-egress` namespace on the existing default outbound subnet for
collateral only. Its bounded CONNECT proxy permits Intel PCS/certificate hosts
and AMD KDS on port 443, rejects nonpublic DNS results, and forwards TLS bytes
without terminating TLS. Guest verifiers still validate vendor certificates,
signatures and revocations. Only owned CDS guests may reach the proxy; its route
remains available during the CDS/metadata partitions. Existing NAT mappings,
subnet settings and gateway workloads are not modified. The proxy is an extra
test dependency and is not evidence of production collateral-service HA.

The [collateral preflight](../test/pilot/cds-three-host/results/2026-11-06-collateral-preflight-01.json)
fetched Intel's revocation list through the owned proxy with end-to-end TLS
verification. All four resources were removed and independently confirmed
absent. Native guest startup and the backend comparison remain pending.

The fixed test-control endpoint allows 30 seconds of clock skew for signed
requests, with the existing five-minute maximum token lifetime and strict
expiry/replay checks in its actor. This does not change CDS authorization.
Failed control requests retain safe authentication/clock diagnostics. Startup
attempts are bounded to 30 seconds within the three-minute startup budget.
The first guest's startup is checked before the remaining disks are prepared.
