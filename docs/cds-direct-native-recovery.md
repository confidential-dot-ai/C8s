# Native current-state recovery rehearsal

This branch connects the [current-state authority](cds-current-state-custody.md)
to the existing [SNP cross-host rehearsal](cds-cross-host-recovery.md). The
explicit `--direct-state --metadata-relay <binary>` runner flags select
transactional current state in the measured CDS launch. The WAL control keeps
its previous defaults. No shared cloud rollout or CI is required.

Three real CDS processes run inside one immutable SNP guest. A separate SNP
custodian derives and delegates capsule custody to that exact measured image
and launch. An independently enrolled second chip retains a sealed recovery
copy. The runner destroys all source guests, confirms their absence, excludes
the original worker, and starts replacement custody and CDS guests on the
second worker. The replacement must recover the original CA, reject the
still-valid spent token, preserve revocation, and read the original secret with
the original workload certificate after a new signed authorization.

The guest's existing bounded storage relay also transports encrypted current
records. A host-only subprocess invokes the real `metadatapilot.Service` over
a bounded pipe and persists its SQLite file with FULL synchronous commits.
The guest loopback endpoint uses TLS; the helper's internal HTTP adapter is a
test transport, not an exposed network service. Its bearer credential is
generated inside each helper process. The guest credential is explicitly
synthetic and authorizes no production service.

Four network connection owners feed one bounded storage actor. That actor
alone owns the metadata pipe and object store; it never retries a commit after
an uncertain result. Both pipe directions have a size limit and one deadline.
A timeout, process death or mismatched response closes the helper and fails
the rehearsal. Each phase reopens the persistent metadata file in a fresh
helper process, including recovery after all source guest memory is gone.

Local checks cover cold commit/read, stale CAS rejection, refusal to reinstall
an old record version, namespace isolation, blocked pipe reads and writes,
process death, oversized responses, and cleanup. The native guest receipt
must explicitly identify `transactional-current-state` and the current-record
authority; a successful WAL receipt cannot satisfy this arm.

This remains a bounded correctness fixture. Three CDS processes in one guest
do not prove availability across three hosts. The single-host metadata helper
is not an HA metadata deployment. At least one enrolled hardware root and its
sealed copy must survive. Fixed-image custody, future image retirement and
loss of every enrolled chip need separate qualification. TDX attestation has
been qualified separately, but TDX custody and CDS recovery are not established
by this SNP test. Full acceptance and production readiness remain false.

Only owned expiring resources are created in the existing test namespace.
Deletion uses recorded UIDs, and a separate read-only audit checks resource
absence. Raw attestation evidence, platform measurements, launch bytes and
private runner files remain outside the repository; publication uses an
explicitly selected summary.

The [native execution](../test/pilot/cds-sealed-recovery/results/2026-11-05-direct-native-recovery.json)
passed at frozen source `872f6cdd`: seven independently attested guest instances
on two distinct SNP chips, with the current-state backend and recovery authority.
After every source CDS and custody guest was destroyed and the source host was
excluded, replacements recovered the same CA, rejected the still-valid spent
token, preserved revocation, and used the original certificate and secret after
reauthorization. The key and CA remained behind the measured custody/grant path.

UID-scoped cleanup completed, followed by an independent read-only audit of all
36 recorded resource paths with none remaining. No unexpected cluster regression
was observed. Local metadata/custody race tests, 33 runner checks and the real
metadata pipe's cold-reopen and stale-CAS checks also passed. The limits above
remain in force; this is not a production-readiness or three-host availability
claim.
