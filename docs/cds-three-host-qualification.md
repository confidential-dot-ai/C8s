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
used. The [Raft baseline](../test/pilot/cds-three-host/results/2026-11-06-raft-three-host.json)
and [direct-state comparison](../test/pilot/cds-three-host/results/2026-11-06-direct-three-host.json)
both completed on three distinct TDX workers with the same guest images, client,
workload and deadlines. Controller observation corrections and unsuccessful
attempts are retained below.

| Qualification | Raft | Direct current state |
| --- | ---: | ---: |
| Required phases passed | 60/60 | 56/56 |
| Native TDX guest incarnations across three workers | 6/6 | 6/6 |
| Burst: 24 certificate issuances/renewals and 24 secret releases | 25.718 s | 26.738 s |
| Isolated-guest refusal, majority service and revocation | Passed | Passed |
| Observed authority quorum loss, refusal and recovery | Passed | Passed |
| All three image replacements, same CA, replay rejection and revocation | Passed | Passed |
| Signed image retirement applied | Passed | Passed |
| Owned resources removed / paths independently confirmed absent | 35 / 47 | 63 / 78 |

Raft's four additional phases are three membership admissions and one extra
leader-status check. The fault mechanisms differ as described below. Timings
are single observations, not a speedup, capacity or SLO result. This establishes
the bounded HA behavior of direct-state CDS with the dedicated metadata service.
The next qualification must combine this service with hardware-protected key
custody and total CDS replica loss; this run uses the synthetic state key above.

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
absent. Both completed backend qualifications subsequently passed native CDS
startup across all six guest incarnations on three distinct workers.

The fixed test-control endpoint allows 30 seconds of clock skew for signed
requests, with the existing five-minute maximum token lifetime and strict
expiry/replay checks in its actor. This does not change CDS authorization.
Failed control requests retain safe authentication/clock diagnostics. Startup
attempts are bounded to 30 seconds within the three-minute startup budget.
The first guest's startup is checked before the remaining disks are prepared.
Kubernetes reads returning 429 or transient gateway errors (502/503/504) use at
most four attempts with bounded backoff and respect `Retry-After`. A proxy
CONNECT rejection with status 502/503/504 can also be retried within that budget:
Python raises it before TLS or any Kubernetes request is sent. An API response,
unknown transport failure or uncertain mutation never permits a write retry.
The complete health
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

[Attempt 18](../test/pilot/cds-three-host/results/2026-11-06-raft-attempt-18.json)
passed startup on all three workers and the native burst (24 issuances and 24
secret reads in 25.697 seconds). All six disk hashes matched. Removing the final
disk-population pod encountered a proxy CONNECT 502 before the API request could
be dispatched; the precise API method was not recorded. No fault was injected.
All 32 owned resources were removed and 41 paths independently confirmed absent.
The bounded CONNECT handling above is covered by a real local proxy test that
observes only CONNECT requests, with no origin authorization header or body.

Raft attempt 19 completed the entire qualification: 24 issuances and 24 secret
reads in 25.718 seconds; isolated-leader refusal and majority service with
revocation; observed two-guest pause and quorum-loss refusal; recovery with the
same CA and replay rejection; all three image replacements; and applied image
retirement with revocation preserved. All 35 owned resources were removed.
Twelve initialization handshakes timed out before dispatch and reconnected
within the startup budget; no workload phase or image upload needed a retry.
This is one completed bounded qualification, not an availability SLO or a
replacement recommendation. Earlier unsuccessful attempts remain above.

[Direct-state attempt 1](../test/pilot/cds-three-host/results/2026-11-06-direct-attempt-01.json)
passed native startup and provisioning on three workers. Genesis, serving
checks, the initial policy and secret, and the same-CA check completed, but the
first certificate issuance to replica 1 timed out waiting for HTTP response
headers. Etcd also logged peer connection timeouts involving that worker; this
does not establish a CDS or infrastructure root cause. Its console disconnected
during the phase, leaving incomplete guest-side evidence. No fault or workload
burst was reached. All 51 resources were removed and 60 paths independently
confirmed absent. Failure diagnostics now reconnect existing owned consoles and
capture bounded, fixed CDS status reads and metadata member statuses before
cleanup. These probes cannot replay a failed workload or change its result.

Read-only [network observations](../test/pilot/cds-three-host/results/2026-11-06-worker-network-observations.json)
found a new regression on the `poc115-node` / `poc115-node-2` pair. The existing
OVN pinger recorded no losses in 693 pod probes during the successful Raft
window, then 41 losses in 54 probes around the direct-state failure and 38 in
39 recent probes. Reciprocal probes also lost packets. Node probes reported
individual sample averages exceeding 17 seconds. Both nodes still reported
Ready; their inspected queue counters had no drops or backlog. Peer-node routes
used the physical interfaces and their gateways. These observations establish
a network regression overlapping the failure, not its complete root cause.
ICMP probes and CDS use different workloads and may use different subnet paths.

[Direct-state attempt 2](../test/pilot/cds-three-host/results/2026-11-06-direct-attempt-02.json)
was stopped before guest boot or fault injection after that regression was
confirmed. Its metadata quorum and collateral preflight had passed, showing why
those checks alone were insufficient. The ordinary cleanup removed all 38 owned
resources; the independent audit confirmed 42 paths absent. No host networking,
OVN configuration, route, queue or shared policy was changed. Resuming required
observed recovery of worker connectivity, a repeat metadata check and the same
direct-state workload and deadlines. These incomplete attempts alone support
neither a production replacement nor a performance comparison.

The loss persisted after cleanup: the independent audit finished at 14:09:52 UTC;
existing probes between 14:13:34 and 14:16:25 lost 15 of 18 pod probes and 3 of
21 node probes on the pair. CDS timeouts and qualification requirements remain
unchanged.

Further [network observations](../test/pilot/cds-three-host/results/2026-11-06-worker-network-recovery.json)
separated the physical and pod paths: simultaneous host probes received 30 of
30 replies in each direction, while pod probes received only 1 and 2 of 30.
Sampled encrypted packet headers matched across both hosts; some decoded probe
packets reached their destination pods late in batches. These observations do
not identify the precise queue or establish a root cause. No shared network
configuration was changed.

The existing pod probes subsequently recorded 93 of 93 replies in each direction
between approximately 14:53 and 14:59 UTC. Fresh one-second probes then received
60 of 60 replies in each direction, with maximum RTTs below 3 ms. This observed
recovery permits another owned qualification with network monitoring; it does
not establish a permanent repair.

The [repeated metadata qualification](../test/pilot/cds-three-host/results/2026-11-06-ha-metadata-repeat.json)
passed all 64 independent commits, one winner among 16 conditional contenders,
both fault scenarios and recovery of all 65 acknowledged records through each
adapter. An earlier repeat failed an independent-write batch without retaining
individual outcomes; that failure remains unexplained. The successful repeat
changed only runner diagnostics. Its 29 resources were removed and 32 paths
independently confirmed absent before resuming the unchanged direct-state run.

[Direct-state attempt 3](../test/pilot/cds-three-host/results/2026-11-06-direct-attempt-03.json)
passed 22 phases, including native startup on all three workers, the 24-issuance /
24-secret-release burst in 26.910 seconds, isolated-guest refusal, majority
service and revocation, and recovery with the same CA and replay rejection.
All six disk hashes matched without upload retries. Quorum-loss observation then
failed before CDS's refusal phase: the leader logged that it stepped down, but
one member's status tunnel was unavailable in the subsequent diagnostic and its
forward log reported a lost connection. Fault-time member responses were not
retained, so the complete observation failure cannot be reconstructed. No rolling
replacement was reached. All 60 resources were removed and 72 paths independently
confirmed absent. One existing probe interval lost three packets; subsequent
samples, including the fault window, were clean.

Before the next metadata fault, the controller closes its three old status
tunnels, reopens them against the exact owned Pod UIDs, and verifies a healthy
three-member view in the original cluster. The unchanged 20-second quorum-loss
observation budget now retains every sample and requires all three verified
members to answer with no leader. Unavailable or wrong members cannot satisfy
that check. Only read-only observation connections change; guest images, client,
workload, CDS deadlines and fault policy are unchanged. Local regressions cover
unknown responses, wrong identities, late results and scoped tunnel cleanup.

[Direct-state attempt 4](../test/pilot/cds-three-host/results/2026-11-06-direct-attempt-04.json)
again passed those 22 phases and the burst, this time in 26.649 seconds. It then
exposed a controller regression before the metadata fault: the observer refresh
unpacked metadata setup's six fields as three. Its unit fixture had made the
same incorrect assumption. The setup now returns a named record, and the
regression executes the real setup method before refreshing observers, replacing
only infrastructure effects. Adapter handles and all other setup fields must
remain intact. All 37 controller tests and six metadata fixture tests pass.
The failed run's 60 resources were removed and 72 paths independently confirmed
absent. One image chunk retried; no workload request did. The CDS binaries,
workload and deadlines remain unchanged.

[Direct-state attempt 5](../test/pilot/cds-three-host/results/2026-11-06-direct-three-host.json)
completed all 56 required phases. The burst issued or renewed 24 certificates
and released 24 secrets in 26.738 seconds. All six full disk hashes matched;
there were no image-upload or workload retries. Twelve initialization tunnel
reconnects occurred before dispatch within the unchanged startup budget.
Single-guest isolation refused a valid release while the majority continued
serving and applied revocation. The fresh metadata observers then independently
confirmed all three members had no leader in 5.494 seconds, within the unchanged
20-second budget. CDS refused a valid release while authority was unavailable.
Recovery, all three image replacements and final image retirement preserved
the CA identity, spent-token rejection and revocation. Cleanup removed all 63
owned resources, and an independent read-only audit confirmed 78 paths absent.

Existing worker-pair probe samples during this run reported no loss. The result
retains an observation gap on the reverse path; sampled ICMP success does not
prove continuous connectivity or every CDS/metadata TCP path. The earlier
network regression still has no confirmed root cause or permanent repair.
No shared network or host configuration was changed. The completed qualification
does not erase the earlier failures or qualify production scale, migration,
mixed-release compatibility, large-object availability or combined key custody.
