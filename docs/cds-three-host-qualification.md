# Three-host CDS qualification

This opt-in fixture continues after the completed three-worker metadata test.
It places exactly three CDS guests on distinct qualified TDX compute workers,
using the production CDS service arguments and pinned production attestation
binary. Workload private keys stay in their guest. A bounded actor accepts only
fixed test phases signed by the measured operator key; the controller verifies
native TDX armTLS, including the complete image tuple and launch file, before
sending a phase. No arbitrary commands, paths, quote service or SSH are exposed.

Raft and direct current-state metadata run sequentially with the same compute
budget, images and workload. The metadata arm uses three dedicated etcd members
and three stateless adapters. Etcd uses Raft internally. CDS's direct-state arm
has no application WAL or Raft participant.

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
