# Reviewing C8s changes

Review the change against the [engineering standards](engineering-standards.md)
and the contract it implements. Read the diff, affected callers and tests before
forming conclusions. For a stacked PR, review against its declared base.

## Focus the review

Prioritize changes to trust boundaries, attestation, authorization, keys, admission,
measured boot and state transitions. Build scripts, Helm values and dependency
updates can change those boundaries; judge their effect from the diff.

For each important path, identify the invariant, who controls its inputs and what
failure looks like. Read the relevant authoritative protocol specification when
checking wire formats, cryptographic profiles or required validation order.

## Correctness and maintainability

- Trace success, rejection, timeout, cancellation, restart and partial-failure
  paths relevant to the change. Check state transitions and resource cleanup.
- Check both ends of changed interfaces, including encoding, error handling and
  compatibility with shipped callers.
- Check that goroutines terminate, deadlines propagate, retries are bounded and
  errors preserve their cause. Bound allocations derived from untrusted input.
- Prefer existing primitives. Check whether abstractions represent actual variants
  and whether names reveal domain meaning and assumptions.
- Check comment usefulness and multiline function signatures against the standards.
  Resolve confusing code through names, types or structure.
- For performance changes, inspect representative benchmarks and resource costs.
  Verify that optimizations preserve validation and authorization invariants.

## Security

- Trace untrusted inputs across the TEE boundary. Authenticate attestation evidence
  before trusting its claims; verify the required chain, policy, measurements,
  freshness and binding to the key or session under the applicable contract.
- Distinguish authenticated evidence from authorization. Check workload identity,
  grants and policy at the point where credentials or secrets are released.
- Confirm that rejection paths fail closed and that retries, fallback behavior or
  cached decisions cannot bypass checks or outlive their validity.
- Use audited cryptographic primitives. Check nonce uniqueness, appropriate secret
  comparisons, key lifetime and accidental exposure in logs, errors or artifacts.
- Trace plaintext data through memory, storage and network paths. Verify where
  encryption and decryption occur relative to the trust boundary.
- Review privileges, mounts, service accounts and network reachability against the
  component's requirements. Check that configuration preserves enforcement.
- For build or dependency changes, check source and artifact identity, digest pins,
  reproducibility requirements and effects on attestation measurements.

## Test and documentation evidence

- Name the bug each important test would catch. Check its assertions, negative
  cases and boundary conditions, including validation order where relevant.
- Distinguish mocked or ordinary Kubernetes coverage from execution on the claimed
  confidential platform. Record skipped coverage and workarounds explicitly.
- Check that examples, CLI help, defaults and configuration match the implementation.
  Follow tutorial steps literally when safe; identify desk-checked steps otherwise.
- Review the final diff for unrelated work and ensure the PR describes its current
  scope and the areas requiring human attention.

## Report findings

For each finding, give the location, observed behavior, consequence, evidence and
smallest useful correction. Rank by impact and distinguish confirmed defects from
questions requiring more evidence. State when no actionable findings were found,
along with any remaining coverage limits.

Keep vulnerability evidence in the channel defined by [SECURITY.md](../SECURITY.md).
Handle recurring corrections through [AGENTS.md](../AGENTS.md#learn-from-review-feedback).
