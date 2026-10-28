# Encrypted volumes

On a confidential node, a volume's plaintext exists only inside that node's CVM,
and CDS releases its key only to a pod whose containers match an entitled
allowlist entry; every pod on the node shares that boundary.

Guarantee: [Data stays in the TEE](guarantees.md#data-stays-in-the-tee),
[Only allowlisted code runs](guarantees.md#only-allowlisted-code-runs).

An encrypted volume is data too large to be a secret — model weights above all —
encrypted at rest on storage the host can read and write. Its key is a secret in
CDS, the Certificate Distribution Service holding C8s policy and the secret
store, released by the machinery in [secrets.md](secrets.md). Steps are in
[workloads.md](workloads.md), names in [glossary.md](glossary.md).

## Why a volume is different from a secret

Every other value C8s protects is RAM-resident and dies with the pod. A volume
does not: its ciphertext sits on storage the host keeps, so a leaked volume key
is retroactive and permanent — it decrypts a copy the adversary already has. The
key must also be in the store first: the fetcher only reads.

## The artifact

`c8s volume create` builds an immutable image, or writable with `--mutable`.

| | immutable (default) | mutable (`--mutable`) |
|---|---|---|
| filesystem | erofs, read-only by construction | ext4, read-write |
| integrity | dm-verity, hash tree inside the encryption | none |
| confidentiality | plain dm-crypt, `aes-xts-plain64`, 512-bit key, 512-byte sectors | same |

The pieces are the standard Linux ones: `dm-crypt` is the kernel's block-layer
encryption and `aes-xts-plain64` its usual full-disk mode; `erofs` is a
read-only filesystem; `dm-verity` is a kernel hash tree checking each block
against a root hash.

A mutable volume trades integrity away: dm-verity cannot cover a writable
device, so the host can flip bits or roll it back undetected. On an immutable
volume both are detected, but lazily: a modified block surfaces as an I/O error.

There is no LUKS header. Its on-disk metadata is protected only by a checksum
the host can recompute, and the TEE would parse it with root privilege on every
open. Every parameter comes from the key blob instead, and the hash tree sits
inside the encryption because a tree in the clear fingerprints the plaintext.

### The key blob

The key blob stored at the secret path holds all that opening the volume needs,
and nothing else.

```json
{ "type": "c8s.volume/v1", "key": "<base64, 64 bytes>",
  "verity": { "root_hash": "<hex>", "salt": "<hex>",
              "data_blocks": 26214400, "hash_offset": 107374182400 } }
```

The root hash rides here rather than in an annotation or the entry because it is
the integrity anchor, and an anchor the host can edit anchors nothing. A mutable
blob carries `"mutable": true` and no tree; one with both or neither is refused.

### Keep the escrow file

`--escrow-out` is required, written `0600`, and refuses to overwrite. It is the
only copy of the key outside CDS, which holds secrets in process memory, so a
CDS restart makes every volume unopenable until its key is written back with
`c8s secrets put <PATH> --from-file <ESCROW>` and that command's write flags —
`--url`, a measurement pin, `--operator-key`, and the `--mesh-ca` bundle CDS
must serve. Lose the escrow file and the ciphertext is gone for good. What else
a restart drops is in [operator.md](operator.md).

### The device

The image is ciphertext, so it travels by any means, including through the host.
The node finds it as a raw block device whose disk serial is `c8s-vol-<name>`.
That serial is a selector, not a trust input: the host chooses it, so the wrong
device fails closed on the key or the root hash. A volume has to be a device
rather than a file on the node's filesystem, because a node running the C8s node
image — the measured guest image — keeps its writable state on an ephemeral disk
that no reboot survives. The device is attached to one node, so the pod must be
pinned there, with the `nodeSelector` that `c8s volume create --node` prints.

### Attaching the image

Three ways present the image to a node, and which ones are open is fixed at VM
launch. The commands are in [workloads.md](workloads.md).

- **Cold-plug virtio-blk**: attaches the disk when the VM starts, and is the
  only way to add a virtio-blk device at all, since PCI hotplug is compiled out
  of the C8s node image's kernel.
- **Hot-attach `scsi-hd`**: adds a disk to a running VM, on the node image too,
  but only onto a virtio-scsi controller provisioned at launch.
- **`c8s volume attach`**: builds a local disk through the kernel's SCSI target
  subsystem (LIO), which the C8s node image leaves out, where no hypervisor can
  set the serial.

## The mount policy

A volume consumer's workload entry — the allowlist entry naming the images the
pod may run — needs a `secrets` grant for the key's path and a mount rule for
the opened volume. A grant requires every container's mount policy to be `exact`
or `deny`: `exact` lists each mount the container may have, by destination and
kind, and `deny` admits none. So a consumer carries one `data` rule per volume
at `<volume-dir>/<NAME>`, by default `/mnt/c8s-data/c8s-volumes/<NAME>` and
otherwise where `confidential.ai/c8s-volume-dir` points inside `/mnt/c8s-data/`,
while a container that mounts nothing carries `deny`. Grant the exact path, not
a subtree: the annotation naming which volume to open is host-written.

## Opening a volume

A pod names its volumes in `confidential.ai/c8s-volumes`, as `NAME=/store/path`
pairs. The webhook injects the `c8s-volume` sidecar and a per-volume `emptyDir`
the node's mount propagates into. The sidecar fetches the key over the attested
secrets flow and posts it to volumed, the node agent, which opens the device and
mounts it into that pod: read-only erofs under dm-verity, or read-write ext4.

Three things decide whether a mount happens. CDS releases the blob to the pod's
sandbox, on the checks in [secrets.md](secrets.md). volumed mounts into the
calling pod's directory and no other: it takes the caller's identity from the
kernel, by resolving the connecting process's cgroup, so a caller cannot name
another pod and have the plaintext mounted there. And the device opens only if
the key fits and, for an immutable volume, the root hash matches.

So the volume appears after the workload starts, on the same gate as a secret.
If one is already open under the pod, a second request must present the same
key, mode, and root hash. Without that check the volume's name alone would open
it, and the name is a label in an annotation the host writes.

One writer per device: two read-write mounts of one device corrupt the
filesystem, so volumed refuses a device carrying a mutable mount, or a mutable
open on one carrying any mount. Give a mutable consumer one replica or a
`Recreate` strategy; immutable volumes share freely.

On a node running the C8s node image, volumed runs as the host service
`volumed.service`, because the image fixes the paths it needs. Everywhere else
it is a chart DaemonSet, off by default because it is privileged, with `hostPID`
and a writable kubelet-directory bind; `--volumes` on `c8s install` turns it on.

### Teardown

Releasing the volumes is the sidecar's last act: the kubelet stops sidecars only
after the workload's containers exit, so the close lands while nothing holds the
mount and before the kubelet's `emptyDir` cleanup could delete files through a
live read-write mount. A cgroup reaper collects after pods that die without it.

### Possession of the blob is the authorization

volumed does not repeat CDS's release decision. It resolves who is calling only
to decide where to mount: any pod reaching its socket with a well-formed blob
has that volume opened into its own directory. That holds only while the
daemon's reach is one tenant's — the node is the confidential VM, and every pod
on it shares that boundary, so a blob one of them can obtain is one they are all
entitled to. Run volume workloads on single-tenant nodes.

## Uninstalling, and what is left behind

`c8s uninstall` refuses while a pod holds a volume, because volumed is the only
thing that unmaps one. Scale those workloads to zero first. `--force` proceeds
and names the pods it passed: their mappings stay open, since the chart's
pre-delete hook cannot close a device a live mount namespace references, and an
open mapping holds its backing disk open against the next install.

No shell on the node is needed: volumed sweeps the C8s mappings it finds at
startup, so reinstalling reaps what an uninstall left; a reboot clears them.

A disk built by `c8s volume attach` is separate state. The host sweep, on by
default, removes the idle ones and names any still held; a release whose pinned
sweep predates that step leaves them and the uninstall says so, and
`c8s volume detach <name>` then removes one by hand.
