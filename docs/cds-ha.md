# Highly available CDS: operator notes

"Workload policy" below is what the API and CLI call the allowlist.

These notes cover running CDS as several replicas that share one mesh CA
(`launch-config new --cds-node`). Each step below was run on TDX hardware.

## Starting an HA cluster

HA CDS starts with a **fresh launch**. A cluster that runs a single CDS
(no `cdsHA` in its launch documents) does not convert in place. Create a new
bundle with `c8s node launch-config new --cds-node <name>` (repeat the flag:
an odd number, 3 to 9), launch every node, and apply the Genesis decree. Then move
workloads and re-apply the workload policy (`c8s allowlist apply`) and secrets.

## Rolling CDS to a new image

1. Sign and apply an `UpdateMeasurements` decree that pins both images
   (`c8s cds ha decree --image <old> --image <new>`). Nodes and pods follow
   it. No node is relaunched for this.
2. Replace the cds nodes one at a time, the leader last. Each replacement
   gets a **new name** (`c8s node launch-config add-cds-node --image-manifest
   <new manifest.json>`). Wait until the new replica serves before you remove
   the old node.
3. Sign and apply a decree that pins only the new image.
4. Remove the old image's workload policy entries. They stay until you do.

When the new release reads a newer state format, the cluster changes format
by itself. That happens when every seat is filled by a replica that reads the
new format, so during the rollout the old format stays in force.

The router, `get-cert`, the injected sidecars and `allowlist-proxy` follow the
decrees through the node's enforcer.

## Application policy and read freshness

Genesis records application policy version 1 in the replicated Core: the exact
sandbox binding TTL and capacity, and the secret path, per-holder and value
limits. These values are immutable for that cluster. Every joining replica
must use identical effective values. Missing, unknown or different policy is
refused before membership or snapshot state changes. Recovery uses the same
policy as live application, including refused logged commands. Policy version
is separate from snapshot format. The format-3 release requires a clean
redeploy; it does not infer policy for old clusters or support format-2 restore
or rolling conversion.

Local authorization reads are **bounded stale, not linearizable**. Each replica
periodically asks the leader for a Raft barrier, then waits until its own FSM
has applied the returned watermark. The read certificate expires one Lease
(default five seconds) after the request **started**. Heartbeats alone never
renew it. A changed Raft instance, leader, term or decree epoch invalidates it.
HTTP admission, CA access and readiness check this evidence locally. Ordinary
GET requests do not append log entries. Explicit CatchUp calls force a barrier.
At a Lease/3 refresh interval the default cost is at most about 0.6 barrier
entries per replica per second, plus explicit CatchUp calls; test settings with
a one-second Lease use about three per replica per second. If application or
quorum confirmation stalls, replicas stop admitting reads when evidence expires.
This is an admission-time guarantee, not an atomic transaction around an entire
HTTP handler that was already admitted.

Genesis fallback fails closed on discovery errors and unreachable discovered
peers, and never replaces locally known cluster state. A successful **empty**
discovery result still permits the explicitly signed initial Genesis. Stateless
reboots cannot distinguish a true first launch from replay of a still-valid
Genesis when discovery hides all existing members. Complete prevention needs a
trusted one-time boot generation or new operator authorization; this change
does not claim to provide that marker.

## Checking the replicas

    c8s cds ha status --image-policy-file server.json https://<node-1>:30808 https://<node-2>:30808 ...

`status` reads `GET /ha/status` from each replica over armTLS, with the same
connection flags as the other `c8s cds` commands. It prints each replica's
role, epoch, mesh CA and applied index, and fails when a replica cannot be
reached, is not serving, or disagrees on the epoch or mesh CA. A status is the
replica's own report; `c8s cds ha decrees` gives the agreed decree record.

## The mesh CA certificate

The replicas share one mesh CA key for the life of the cluster. Past half the
certificate's lifetime (`--ca-cert-validity`, one year by default), the leader
renews the certificate under the same key through the log, so every replica
serves the same new certificate and running workloads keep their trust anchor.
Replacing the key itself is the `RotateKey` decree, a break-glass step.

## Rebooting nodes

* A rebooted cds or agent node rejoins under its own name. A rebooted voter
  loses its state and comes back as a new member. The cluster gives its seat
  to another replica.
* **A server-node reboot starts a new, empty cluster.** The server keeps
  all cluster state on the per-boot encrypted scratch disk (see
  operator.md, "Revocation is a launch-time decision"). That includes the CDS
  backups, because they are ConfigMaps in the same etcd. Surviving the loss
  of the control plane is the job of server HA, which is tracked separately.
  Until then, a backup you exported earlier (below) is the way back.

## Backups

The leader seals the state to the recovery key and stores it at most once a
minute. Writes made after the last backup are lost
in a total loss, so the window is up to one interval.

**Export the backup off the cluster on a schedule.** The backup is sealed to
the recovery key, so you can store the export anywhere:

    kubectl get configmaps -n c8s-cds-decrees \
      -l c8s.confidential.ai/cds-backup=<cluster-id> -o json > cds-backup-$(date +%s).json

Also record the epoch and index the backup shows (`c8s cds ha recover`
prints them, and so does the backup manifest). Recovery refuses a backup
older than the `--min-epoch`/`--min-index` you give it.

## Splitting the recovery key

    c8s cds ha recovery-key split --recovery-key recovery.key --out shares --shares 5 --threshold 3

Give each `share-N.json` to a different custodian, then destroy
`recovery.key`.

## Recovering from a total loss

Use this when every replica lost its state:

    c8s cds ha recover --url <cds url> --image-policy-file server.json --operator-key server.key \
      --backup-file cds-backup.json --cluster-id <id> --bootstrap-node <a fresh cds node> \
      --decree-key decree.key --min-epoch <E> --min-index <I> \
      --recovery-key-share share-1.json --recovery-key-share share-3.json --recovery-key-share share-4.json

Fewer shares than the threshold are refused. The restored cluster keeps its
mesh CA, secrets, workload policy and decree record, and the other replicas join it.
If an attempt's answer times out while the replica restores, `recover` checks
the decree record and reports success when its own Restore is there.
