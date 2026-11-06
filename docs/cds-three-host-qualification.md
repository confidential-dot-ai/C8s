# Three-host CDS qualification

This opt-in fixture continues after the completed three-worker metadata test.
It places exactly three CDS guests on distinct qualified TDX compute workers,
using the production CDS service arguments and a pinned attestation binary
with the bounded TDX quote worker described below. Workload private keys stay
in their guest. A bounded actor accepts only
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

The first guest fault uses the owned NetworkPolicy. The Raft quorum-loss fault
pauses the two owned guest VMIs, observes their `Paused` conditions, then waits
longer than the five-second read lease. It resumes those same incarnations in a
`finally` block, including after a partial or ambiguous pause failure. Guest
UID, controller ownership, labels and placement are checked before and after
each action. No host is paused. Three answered statuses with the same three
voters and one observed leader are required before each Raft fault. The metadata
arm uses its dedicated member policies and observes loss of a metadata leader;
the two fault mechanisms are reported separately.

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
absent. Native CDS startup subsequently passed on three distinct workers; the
backend comparison remains pending.

The fixed test-control endpoint allows 30 seconds of clock skew for signed
requests, with the existing five-minute maximum token lifetime and strict
expiry/replay checks in its actor. This does not change CDS authorization.
Failed control requests retain safe authentication/clock diagnostics. Startup
attempts are bounded to 30 seconds within the three-minute startup budget.
The first guest's startup is checked before the remaining disks are prepared.
Kubernetes reads returning 429 or transient gateway errors (502/503/504) use at
most four attempts with bounded backoff and respect `Retry-After`. Writes and
nontransient failures are not automatically retried. The complete health
preflight must succeed before resource creation.

Agent attestation alone is not CDS readiness. A separate fixed startup phase
checks guest DNS, reachability of the owned collateral proxy, and the actual
CDS service's attested status before more disks are prepared. The image explicitly
routes `cluster.local` to DHCP-provided DNS. Transfers use 8 MiB frames, at most
three fresh-path attempts with backoff, and retain failed receiver byte counts.
The fixed phase client uses a five-minute header and overall response budget:
genesis and recovery may legitimately wait longer than the standard armTLS
client's ten-second header timeout. Its verified TLS transport is retained.

[Attempt 10](../test/pilot/cds-three-host/results/2026-11-06-raft-attempt-10.json)
reached workload issuance, where a one-second issuer/consumer clock difference
caused strict X.509 verification to reject a new leaf. The next image backdates
leaf validity by at most the existing five-minute skew allowance, capped at one
tenth of its TTL. Expiry moves back equally: the total validity and named-leaf
revocation ceiling do not increase. Both backend arms use this same change;
the harness still uses ordinary X.509 verification with the consumer's clock.
CA validity and host clocks are unchanged.

[Attempt 11](../test/pilot/cds-three-host/results/2026-11-06-raft-attempt-11.json)
passed initial issuance and secret reads on all three guests, then failed the
concurrent issuance burst. Its fallback console command used an invalid timeout
format, leaving the guest assertion unavailable. The cause remains unresolved;
the same frozen CDS binary passed the local Raft workload with mock attestation.
The next runner captures each owned guest's console from boot into a private
1 MiB tail. One writer owns each tail, and its pipe supplies backpressure. It
keeps a terminal open but sends no keystrokes; capture processes stop with their
owned guests. Initial workload checks now precede copying replacement disks,
while every fault still waits for all six disks to be independently verified.
The workload, request timeouts, image pins, and backend budgets are unchanged.

[Attempt 12](../test/pilot/cds-three-host/results/2026-11-06-raft-attempt-12.json)
stopped at the runner's console-liveness guard after a quiet console stream
disconnected; no workload or fault result was reached. Capture now reconnects
before a phase, revalidating both VM and guest UIDs and waiting for a new
connection acknowledgment. Two attempts are allowed per reconnect. It retains
the same bounded tail, explicitly marks possible output gaps, and cannot treat
an old connection message as proof of a new connection.

[Attempt 13](../test/pilot/cds-three-host/results/2026-11-06-raft-attempt-13.json)
reproduced the burst failure with working console capture: three workload secret
reads received EOF, and the destination logged TLS handshake read timeouts. CDS
allows five seconds for that handshake, while the client attester was generating
TDX quotes at approximately one-second intervals. The pinned attester performs
blocking ConfigFS/vsock quote I/O directly on async workers. The next qualification
uses a separate attester branch with one hardware worker and a bounded message
queue, allowing verification to run while quote generation waits. No CDS timeout,
attestation policy, or workload limit is relaxed. All 29 fixture resource paths
were independently confirmed absent after this failed attempt.

[Attempt 14](../test/pilot/cds-three-host/results/2026-11-06-raft-attempt-14.json)
passed the native burst: 24 issuances and 24 secret reads in 25.812 seconds with
the bounded quote worker and unchanged CDS workload/timeouts. Leader isolation
also passed refusal, majority service, replay rejection and revocation. The
subsequent intended quorum loss returned HTTP 200. Three voters were confirmed,
but vote RPCs still appeared during the intended isolation; a policy update
alone did not establish complete loss of connectivity. This is a failed test,
not proof of a Raft safety violation. All 32 owned resources were removed and
41 resource paths independently confirmed absent. The next run uses the
observable guest pause fault above to establish quorum loss.

[Attempt 15](../test/pilot/cds-three-host/results/2026-11-06-raft-attempt-15.json)
stopped before dispatching the burst: host-side native attestation verification
hit its deadline during the control TLS handshake. Three guests had passed
startup, seeding and attachment. No fault was injected, and all 29 resource
paths were independently confirmed absent. This exposed the need to distinguish
a failed control handshake from an uncertain dispatched phase.

[Attempt 16](../test/pilot/cds-three-host/results/2026-11-06-raft-attempt-16.json)
passed 39 phases: the native burst, leader isolation, majority service, replay
rejection, revocation, observed two-guest pause, quorum-loss refusal, recovery
and the first rolling image replacement. The next preparation phase could not
start after the Kubernetes websocket proxy returned HTTP 503; `virtctl` left
its local socket open and the control handshake stalled until the overall
deadline. All 43 resource paths were independently confirmed absent.

The pilot client now bounds TLS handshakes to 15 seconds and returns a dedicated
exit status only for a TLS timeout before HTTP headers were written. The runner
revalidates the owned VM/VMI incarnation, replaces that tunnel, and retries a
workload phase once within its original deadline. It records the failed attempt
and restart. A workload phase is never retried after attestation or pin rejection,
a returned receipt, or an uncertain dispatch. Idempotent initialization retains
its existing three-minute startup window, with three-second reconnect backoff
and no retry of a returned receipt. Local tests cover the stalled listener,
the startup window and prevention of uncertain phase replay.

[Attempt 17](../test/pilot/cds-three-host/results/2026-11-06-raft-attempt-17.json)
exposed a runner regression: applying the one-retry cap to initialization cut
boot readiness short after two 15-second TLS deadlines. No CDS startup or
backend result is claimed. The correction restores only the existing idempotent
startup window; guest binaries, workload retries and workload limits are unchanged.
