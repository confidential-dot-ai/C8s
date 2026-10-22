# Highly available CDS: operator notes

"Workload policy" below is what the API and CLI call the allowlist.

These notes cover running CDS as several replicas that share one mesh CA
(`launch-config new --cds-node`). Each step below was run on TDX hardware.

## Starting an HA cluster

HA CDS starts with a **fresh launch**. A cluster that runs a single CDS
(no `cdsHA` in its launch documents) does not convert in place. Create a new
bundle with `c8s node launch-config new --cds-node <name>` (repeat the flag,
at least two), launch every node, and apply the Genesis decree. Then move
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

The leader seals the state to the recovery key and stores it at most once per
`--ha-backup-interval` (1 minute). Writes made after the last backup are lost
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
