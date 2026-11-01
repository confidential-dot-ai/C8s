# Cloud Pod acceptance

This lane tests signed `c8s-launch/v2` Pod guests against a separately measured
CDS VM. See [inputs and scenarios](../../../docs/integration-tests.md#pod-cloud-acceptance)
for running `connected`, `warm-assignment`, `verification-timeout` and `cds-outage`.

New runs require deployed Cloud API/operator support and independently admitted
`c8s-pod@<version>` and `c8s-cds@<same-version>` artifacts from the recorded source.
Pod launches retain their PEM launch key and signed v2 document. CDS uses the
`c8s-cds/1` launch contract with `launchFile` access and only
`trust.initData: {format: "c8s-cds/v1", document: "<base64 exact config bytes>"}`.
Its request contains no launch key, signature or extra disks. The sole
`opkeydata/pubkey` file is the decoded configuration, whose hash binds ownership
and whose measurements pin direct armTLS on port 8443. Readiness uses the
attested CDS CA, with no TCP readiness probe or node-status endpoint.

The runner generates the configuration and pin through `c8s cds config new` and
checks both against the same exact local inputs before provisioning. Pod assignment,
CDS policy writes and server identity have distinct keys. The current production
schema requires node pins and a node subnet: the harness supplies a separate
run-local server authority and `10.0.0.0/24`, but never launches a node under that
key. It remains cluster identity context, with no Pod assignment or CDS write
authority; production validators are unchanged.

Every scenario authenticates the initial policy and proves unsigned, Pod-key and
server-key writes are refused without changing it. Transport failures cannot
satisfy that proof. Result version 2 binds both manifest/disk pairs, CDS configuration,
scenario assertions and the actual provider executable. Cleanup alone is not a pass.

Historical v1 receipts remain evidence only for their recorded source and image
pins. For an existing run, retain its private state and original runner, then use
`run.sh cleanup /absolute/existing-private-state`. Cleanup reuses the original
`provider.test` and ownership ledger; it does not rebuild or apply the current
launch parser. Never replace that saved binary to upgrade a run. Missing local
interruption proof never authorizes deletion: exact owned Cloud receipts remain
required. Keep all credentials, signed launch material and diagnostics private.
