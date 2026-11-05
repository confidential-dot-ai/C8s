# CDS image transitions with durable recovery

The protected object-WAL and transactional-metadata backends now accept signed
`UpdateMeasurements` decrees through the public CDS endpoint. The existing FSM
checks signatures, versions and launch binding; its encrypted history remains
the only committed image policy. No new policy database or coordination
protocol is introduced. Raft remains the default backend.

Peer forwarding replaces its TLS client and idle connection pool when that
committed policy changes. An immutable policy/client pair is published
atomically, and an older observation cannot overwrite a newer generation.
Forwarding remains owned by the bounded WAL actor; no application mutex or
global admission queue was added. In-flight work and previously issued keys
cannot be recalled by closing idle connections.

## Verified behavior

`TestStorageImageTransitionAndInterruptedRecovery` passed for both protected
storage backends using release CDS binaries, real HTTP/armTLS and separate
processes. Attestation, custody roots and storage are local fixtures.

- An unapproved image boots but receives no recovery grant.
- A signed overlap policy admits the replacement image. An old-image replica
  forwards successfully to the new-image preferred writer without taking over
  because of obsolete TLS pins.
- Losing every CDS process during a mixed-image roll, discarding its local
  allowlist database and restoring the original authority capsule preserves
  the CA, still-valid spent-token rejection and acknowledged revocation.
- After retiring the old image and restarting the authority again, a fresh
  old-image recipient receives no grant. Approved replacements recover the
  same CA; a new authorization lets the original leaf read the original secret.

The inventory fixture explicitly trusts the overlap set for its callbacks.
Recovery-key release independently enforces the current committed policy.
This does not claim that the inventory dynamically follows a retirement decree.

Local evidence is in
[the result record](../test/pilot/cds-sealed-recovery/results/2026-11-05-image-transitions.json).
The affected object backend and recovery-authority race checks and vet pass.
The process scenario completed both arms in 19.63 seconds. This duration is a
correctness-run observation, not a capacity or cloud latency measurement.
No CI, cloud mutation or shared release was used for this increment.

## Remaining hardware boundary

The separate [cross-host SNP proof](cds-cross-host-recovery.md) recovered the same
identity on an independently enrolled chip, using one fixed measured image.
Its bootstrap custodian still delegates only to that exact image and launch.
This change does not broaden that rule or qualify custody-image upgrades.

Native TDX execution and hardware custody require separate qualification.
The current guest kernel exposes native TDX reports but no sealing-key API;
that is a guest-interface gap, not proof that the deployed module lacks sealing.
Retired custody code, loss of every enrolled physical root, and whole-history
rollback outside the trusted-store contract remain explicit limitations.
Full acceptance and production readiness remain false.
