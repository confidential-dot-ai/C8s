"""Summarize observed Go test results without claiming fixture-backed custody."""
import json
from pathlib import Path
import sys


def passed(path):
    events = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    if not events or any(e.get("Action") == "fail" for e in events):
        raise ValueError(f"test stream failed or empty: {path.name}")
    return {(e["Package"], e.get("Test", "")) for e in events if e.get("Action") == "pass"}


def main():
    output = Path(sys.argv[1])
    unit = passed(output / "unit.jsonl")
    process = passed(output / "process.jsonl")
    prefix = "github.com/confidential-dot-ai/c8s/"
    packages = ["internal/cdsrecovery", "internal/cdsconfig", "internal/cdsobject", "internal/cmds/cds"]
    authority_tests = [
        "TestAuthorityRestartCannotRegrantGenesisToReplacement",
        "TestAuthorityRefusesMissingOrRewrittenRegistration",
        "TestAuthorityBackpressureIsPerClusterAndCloseDrains",
        "TestWALAuthorityOriginalCapsuleUsesCurrentPolicyAfterRestart",
        "TestWALAuthorityOrdersRevocationAgainstFinalRead",
        "TestWALAuthorityFailsClosedOnOutageMissingHeadAndLiveRollback",
        "TestWALAuthorityUsesOnlyAppliedSignedPolicy",
        "TestWALAuthorityColdRollbackStillRequiresTrustedStorage",
        "TestWALAuthorityBackpressureIsPerClusterAndCloseCancelsReplay",
    ]
    variants = ["raft", "object-wal", "transactional-metadata", "object-wal-protected", "transactional-metadata-protected", "object-wal-current", "transactional-metadata-current"]
    integration = prefix + "test/integration/cdsha"
    required_unit = {(prefix + p, "") for p in packages}
    required_unit.update((prefix + "internal/cdsrecovery", test) for test in authority_tests)
    required_process = {(integration, ""), (integration, "TestProtectedRecoveryRefusesDowngradeReplayAndMissingHistory")}
    required_process.update((integration, f"{test}/{variant}") for test in ["TestCARotationBackendParity", "TestWorkloadBackendParity"] for variant in variants)
    missing = sorted((required_unit - unit) | (required_process - process))
    if missing:
        raise ValueError(f"required tests did not pass (skips do not qualify): {missing}")
    summary = {
        "scope": "local release-process protocol checks",
        "base_commit": (output / "base-commit.txt").read_text().strip(),
        "worktree_modified": bool((output / "worktree-status.txt").read_text().strip()),
        "local_protocol_result": "passed",
        "backend_scenarios_passed": len(variants) * 2,
        "authority_restart": "passed; restored from signed public enrollment",
        "authority_backpressure_and_cluster_isolation": "passed",
        "same_identity_after_total_cds_loss": "passed for all storage variants",
        "spent_tokens_and_acknowledged_revocation_survive": "passed for all storage variants",
        "tampering_replay_and_missing_history_refused": "passed",
        "current_release_policy": "passed for both current-policy storage arms; original capsule cannot override committed image policy",
        "revocation_ordering": "release linearizes at final head read; overlapping revocation after that read may finish before delivery",
        "retired_custody_code_exclusion": "not established; old code with an independently recoverable key cannot be revoked by this gate",
        "operator_cannot_obtain_ca_key": "unverified: authority keys and attestation use software fixtures",
        "storage_rollback_protection": "not established; linearizable storage remains trusted",
        "full_acceptance_passed": False,
        "production_qualified": False,
    }
    (output / "acceptance.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
