# CDS development branches

As of 2026-11-07, the single active CDS replacement branch is
[`pilot/cds-ha-protected-recovery`](https://github.com/confidential-dot-ai/C8s/tree/pilot/cds-ha-protected-recovery).
Continue implementation and qualification there. The other pilot branches are
historical checkpoints or comparison baselines, not competing development targets.
This consolidation designates the existing branch; it does not create another one.

## Architecture to carry forward

The candidate stores encrypted current records behind a strictly serializable
metadata service. Small ciphertext is inline in metadata; larger immutable
ciphertext lives in object storage. A transaction commits an operator token spend
and its mutation or deterministic refusal together. Bounded per-cluster admission
isolates work, and authorization reads current policy.

CDS replicas keep working state in memory and can be replaced. They have no CDS
application WAL, replay/checkpoint protocol, or Raft participant in this mode.
The qualified HA metadata fixture uses etcd, which **does use Raft internally**.
This moves coordination into the metadata authority; it does not remove the need
for consensus or a trusted freshness authority.

Hardware custody is intended to recover the same CA identity without giving the
infrastructure operator the plaintext state or CA key. The combined qualification
uses TDX CDS recipients and an SNP custodian with a sealed copy on another chip.
See the [current-state protocol](cds-direct-state.md),
[three-host HA results](cds-three-host-qualification.md), and
[combined HA/recovery acceptance](cds-ha-protected-recovery.md).

This is our preferred simplicity candidate, not a demonstrated universal
state-of-the-art result or a production replacement. Separate native HA and
SNP/TDX recovery qualifications have passed. The local combined test has passed
with software custody. **The combined native HA plus total-CDS-loss recovery
proof has not passed.** The latest retained attempt stopped during provisioning
because the harness and measured CDS used different secret-path limits; the
compatibility check refused the mismatch. The local harness correction is
unfinished and is not part of this documentation change.

The next implementation work stays on the active branch: complete and locally
validate that correction, then rerun the combined native proof with the same
identity, live-token replay rejection, revocation and owned-resource cleanup
requirements. Production migration, custody operations, scale limits and trust
in authoritative metadata still need qualification.

## Inventory and scope

The inventory contains **32 distinct branch names across repositories**:
**29 currently published branches and 3 local-only branches**. Names in different
repositories count separately. It covers branches identifiable with this CDS
work, not every branch owned by the author or other managed-Kubernetes work.

| Repository | Branches | Published now | Purpose |
| --- | ---: | ---: | --- |
| C8s | 25 pilots + 1 fix | 26 | Backend experiments, recovery, qualification, production freshness fix |
| cloud | 3 | 2 | Pilot launch settings and merged rehearsal support |
| attestation-rs | 1 | 1 | Bounded TDX quote work |
| confidential-metal | 1 | 0 | Dedicated guest-network support |
| confidential-os-builder | 1 | 0 | Local TDX probe checkpoint |
| **Total** | **32** | **29** | |

No branch ref is deleted by this first cleanup. Historical refs preserve exact
baselines and result commits. A single active development branch does not require
discarding those records, nor merging historical backend modes into production.

### C8s pilot checkpoints

All names below have the prefix `pilot/`. Links pin their published heads at
inventory time, before this documentation commit. Ancestry is measured against
`317a5a8dda88ee54621231d093f4ae7a2980933f`, the active branch's published head
at inventory time.

Of the 24 historical pilot branches, 16 are ancestors of that head and eight have
separate history. Separate history can retain original baseline commits or later
result records even where the implementation was subsequently integrated or
reworked. Do not infer that every historical commit is merged, or blindly merge
the old branches back into the active implementation.

| Branch | What it contributed | Disposition |
| --- | --- | --- |
| [`cds-atomic-operator-write`](https://github.com/confidential-dot-ai/C8s/tree/c0c11f8cb4acae16c48bf7f2bd686993ab390d69) | Commit token consumption and operator mutations atomically | Historical; separate history |
| [`cds-cloud-acceptance`](https://github.com/confidential-dot-ai/C8s/tree/7117600292dc688c7e32a3256e7e32f98cb0633e) | Cloud rehearsal and measured three-backend acceptance | Historical; ancestor |
| [`cds-cluster-concurrency`](https://github.com/confidential-dot-ai/C8s/tree/ead656ddda63a953e71dd08a7e59670b5834487b) | Bound requests and isolate per-cluster actors | Historical; ancestor |
| [`cds-cross-host-recovery`](https://github.com/confidential-dot-ai/C8s/tree/f12fc711292c9ceee4bcddbb19e1dec4f073c2b4) | Recover custody on another enrolled hardware host | Historical; ancestor |
| [`cds-current-release-policy`](https://github.com/confidential-dot-ai/C8s/tree/e58db364f2cccd0ab4480f4bfc53b35cca2f36fd) | Authorize key release from current committed image policy | Historical; ancestor |
| [`cds-current-state-custody`](https://github.com/confidential-dot-ai/C8s/tree/004a24b0fd0bde9b6c72b84638aa389e61ed172a) | Recover custody authority from encrypted current records | Historical; ancestor |
| [`cds-custody-preflight`](https://github.com/confidential-dot-ai/C8s/tree/e708752cab6c0beba1691610ab8289f430ebfb77) | Custody enrollment, sealed backup and failure preflight | Historical; ancestor |
| [`cds-direct-native-recovery`](https://github.com/confidential-dot-ai/C8s/tree/a3cece2b6cb11019d5723585fed6a035ee4699ef) | Native SNP recovery for current-state CDS | Historical; separate history |
| [`cds-direct-state`](https://github.com/confidential-dot-ai/C8s/tree/2d10b67d30c511c15ac3d94a5582bd9c12fabedd) | Replace the CDS application WAL with transactional current records | Historical; ancestor |
| [`cds-ha-metadata`](https://github.com/confidential-dot-ai/C8s/tree/69ec084acdbbafd19bc54af879d23000383ee133) | Qualify replicated metadata authority | Historical; separate history |
| [`cds-ha-protected-recovery`](https://github.com/confidential-dot-ai/C8s/tree/317a5a8dda88ee54621231d093f4ae7a2980933f) | Combine three-replica HA with hardware-protected total-loss recovery | **Active** |
| [`cds-metadata-failover`](https://github.com/confidential-dot-ai/C8s/tree/1854b1302e8b3712933c516a41e587638a1a0da4) | Earlier metadata failover qualification | Historical; separate history |
| [`cds-object-wal`](https://github.com/confidential-dot-ai/C8s/tree/cda2b7a90015ea3333dfb301bc4aef85dd1cf164) | Original encrypted object-WAL/CAS baseline | Historical; separate history |
| [`cds-protected-recovery`](https://github.com/confidential-dot-ai/C8s/tree/20bd0df87cd8eccd3f4031adc534bc3de5ac6c93) | Bind recovery grants to an attested process | Historical; ancestor |
| [`cds-recovery-acceptance`](https://github.com/confidential-dot-ai/C8s/tree/6336e9a1c0942c67934f8133f3fd45089f980791) | Persist recovery enrollment and exercise recovery acceptance | Historical; ancestor |
| [`cds-refresh-before-serving`](https://github.com/confidential-dot-ai/C8s/tree/0e23c96fb9c6714422ac6481b774b58350d481aa) | Refresh authoritative policy before authorization | Historical; ancestor |
| [`cds-snp-recovery-image`](https://github.com/confidential-dot-ai/C8s/tree/adde727e1d982508915a153a4cf361235d8d6479) | Measured SNP image and total guest-loss recovery | Historical; ancestor |
| [`cds-storage-image-transitions`](https://github.com/confidential-dot-ai/C8s/tree/dc774dbb82979cabd68223aff6c647a61b97ee05) | Protected upgrades and image retirement | Historical; ancestor |
| [`cds-storage-lifecycle`](https://github.com/confidential-dot-ai/C8s/tree/e369c226b007711cb39901ff38f2ae4b76fe22e6) | Durable CA renewal and rotation | Historical; ancestor |
| [`cds-storage-scale-comparison`](https://github.com/confidential-dot-ai/C8s/tree/894b632f96e4b9cd640bc015019cac695544ae68) | Independent-path and hot-policy workload comparison | Historical; separate history |
| [`cds-tdx-current-recovery`](https://github.com/confidential-dot-ai/C8s/tree/8950cfa416f4fbc87cd36a9e5a112ffef09f50d6) | Native TDX recovery for current-state CDS | Historical; ancestor |
| [`cds-tdx-recovery-qualification`](https://github.com/confidential-dot-ai/C8s/tree/99e977ccbe5063d5637a7e62033e7c652a45ab3e) | Initial TDX custody/recovery qualification | Historical; separate history |
| [`cds-three-host-ha`](https://github.com/confidential-dot-ai/C8s/tree/240c7456beb2f22cd643e9b507d474b7e6fc5c46) | Matched native three-host Raft and current-state HA comparison | Historical; ancestor |
| [`cds-transactional-metadata`](https://github.com/confidential-dot-ai/C8s/tree/38017aee14b8075bd37b40805dd8c8dda8ab87a7) | Encrypted WAL with transactional commit metadata baseline | Historical; separate history |
| [`cds-wal-replay-progress`](https://github.com/confidential-dot-ai/C8s/tree/a6332b83dbdbd38118e994b39dc9ed31af65019a) | WAL replay and image-transition recovery correctness | Historical; ancestor |

### Other repositories and the production fix

| Repository / branch | Disposition |
| --- | --- |
| C8s / `fix/cds-ha-revocation-freshness` | Keep [PR #1269](https://github.com/confidential-dot-ai/C8s/pull/1269) separate. It fixes freshness in the existing production design and remains open; the replacement pilot does not supersede that purpose. |
| cloud / `pilot/cds-object-wal` | Historical launch-contract support for the original WAL baseline; published. |
| cloud / `pilot/cds-transactional-metadata` | Historical launch-contract support for metadata-WAL; published. |
| cloud / `pilot/cds-cloud-acceptance` | [PR #1149](https://github.com/confidential-dot-ai/cloud/pull/1149) is merged; its remote branch is gone and a local checkpoint remains. |
| attestation-rs / `pilot/tdx-quote-backpressure` | Published support work for bounded native quote processing; separate repository, not an alternative CDS backend. |
| confidential-metal / `pilot/cds-ha-guest-network` | Local-only guest-network support branch; retain separately. |
| confidential-os-builder / `pilot/cds-tdx-readonly-probe` | Local-only probe checkpoint; no published branch. |

No CDS pilot branch was found in c8s-workspace. Other authors' or parallel
workstreams' CDS/cloud branches are outside this cleanup.

## Closed pilot drafts

These four drafts were closed as superseded on 2026-11-07. Their original
descriptions and evidence remain available beneath a supersession notice
pointing here.

| Draft | Disposition |
| --- | --- |
| [#1270](https://github.com/confidential-dot-ai/C8s/pull/1270), bounded request work and cluster actors | Its branch is an ancestor of the active branch; do not maintain it as a separate pilot. |
| [#1271](https://github.com/confidential-dot-ai/C8s/pull/1271), encrypted object WAL | Retain as the original WAL/CAS comparison baseline; current-state development continues on the active branch. |
| [#1272](https://github.com/confidential-dot-ai/C8s/pull/1272), WAL plus transactional metadata | Retain as the metadata-WAL comparison baseline; the current candidate commits current records directly instead. |
| [#1273](https://github.com/confidential-dot-ai/C8s/pull/1273), CA renewal and rotation | Its branch is an ancestor of the active branch; do not maintain it as a separate pilot. |

The cleanup marked these drafts superseded and closed them after explicit
approval for the repository's automatic
[CLA gate](https://github.com/confidential-dot-ai/C8s/blob/main/.github/workflows/cla.yml)
on closure. Their head branches and original comparison evidence are retained;
none of these PRs was merged. The active branch has no consolidated draft PR yet;
opening one is a separate step and also triggers repository automation.

This map is an inventory and development decision. It does not merge a PR,
change production defaults, launch a cloud fixture, or qualify unfinished code.
