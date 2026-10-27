# Onboard a workload

Take your own workload from a plain Deployment to a confidential one: a
workload entry, the pod annotation, a secret, an encrypted volume, and a route.
After step 3, do only the steps you need; terms left undefined here are in
[glossary.md](glossary.md).

## Prerequisites

- A cluster running C8s ([QUICKSTART.md](QUICKSTART.md)) and the operator
  private key you installed it with.
- Every image in the pod template pinned by digest: a tag names whatever the
  registry serves at pull time.
- `kubectl` on PATH, and `crane` for any container that sets no `command`:
  `derive` then reads that image's `Entrypoint` and `Cmd` from the registry.
- `mkfs.erofs` for step 5, or `mkfs.ext4` with `--mutable`: `c8s volume create`
  builds the volume's filesystem with it.

## 1. Open a path to CDS

Allowlist, secret, volume, and route writes go to CDS, which holds the allowlist
and signs workload certificates. They travel over armTLS: mutual TLS whose
certificates carry the peer's TEE evidence, so you verify what CDS runs rather
than a name. The front door relays the allowlist API only, so reach CDS itself:

```sh
CDS=https://<CDS_NODE>:30808
M=<LAUNCH_MEASUREMENT>
PIN="--url $CDS --measurements $M"
KEY="--operator-key c8s-operator.key"
```

`<CDS_NODE>` is the address of any node: the chart publishes CDS on NodePort
`30808` (`cds.service.nodePort`). `kubectl port-forward` is no substitute, since
the measured node image denies it. `<LAUNCH_MEASUREMENT>` is the 96 lowercase
hex characters from your node image's `manifest.json`, the value
`c8s install --measurements` took. Every later step uses `$PIN` and `$KEY`, so
run this block in each new shell.

Confirm the path by listing the entries CDS serves, then read the mesh CA
bundle, the anchor workload certificates chain to:

```sh
c8s allowlist list $PIN
c8s cds ca $PIN --out mesh-ca.pem
```

Secret and volume writes hold CDS to that bundle. A measurement identifies the
image a CDS runs, not which CDS it is, so the read takes whatever answered:
record the certificate SHA-256 it prints on stderr and compare it on later
reads. CDS makes the mesh CA in process, so a restart replaces it and the bundle
has to be read again ([operator.md](operator.md#cds-is-a-singleton) lists what
else a restart drops).

## 2. Write a workload entry

The entry makes your containers admissible, and its name is the identity CDS
stamps on the pod's certificate when exactly one entry matches. Derive it from
the live object, so it covers what actually runs, init containers included:

```sh
kubectl -n <NAMESPACE> get deploy <NAME> -o json |
  c8s allowlist derive <ENTRY> - --env any --mounts deny > entry.json
c8s allowlist apply entry.json $PIN $KEY
```

Use the same `<ENTRY>` string you annotate the pod with. Each container's
command, arguments, environment, and mounts carry a policy: `deny` admits
nothing (for mounts, platform mounts alone), `any` anything, `exact` pins the
values, `match` pins named environment variables. `--env any` and `--mounts
deny` are the loosest useful pair; `--env-file` and `--mounts-file` take a JSON
map of container name to policy instead, as step 6 shows, and a `match` policy
must name every variable the container launches with — the image's, the
runtime's, and the pod's own ([allowlist-entries.md](allowlist-entries.md) has
the field rules). `apply` lints and diffs before the signed write, and the entry
pins argv: re-derive and re-apply whenever the template changes.

Edit a live entry deliberately. Admission is fail-closed and rechecks running
containers — the default in the chart's values and in a baked node image's
measured policy — so narrowing or removing an entry kills the containers it
admitted, within one allowlist refresh (5s).

## 3. Annotate the pod template

Annotate the pod template, not the Deployment's own metadata:

```yaml
spec:
  template:
    metadata:
      annotations:
        confidential.ai/cw: <ENTRY>
```

Roll the workload — `kubectl -n <NAMESPACE> rollout status deploy/<NAME>` — and
check what the webhook injected ([DEMO.md](DEMO.md)). The operator provisions a
headless Service `c8s-<ENTRY>`, which is how other pods in the mesh and the
router reach it.

## 4. Store a secret

```sh
c8s secrets put /tenant-a/db --from-file db.txt --mesh-ca mesh-ca.pem $PIN $KEY
```

The write refuses a CDS that does not serve a mesh CA from `--mesh-ca`, unless
you pass `--force`. Grant the path in the entry as step 6 shows, then ask for
the value on the pod template, beside `confidential.ai/cw`:

```yaml
confidential.ai/c8s-secrets: "DB=/tenant-a/db"
```

Each item is `NAME=/store/path`, and `NAME` is the file written under
`/run/c8s/secrets`. That file appears only after every main container is running
([secrets.md](secrets.md) has the checks CDS makes), so the consumer waits for
it rather than reading it at startup:

```sh
until [ -f /run/c8s/secrets/DB ]; do sleep 1; done
```

On a measured node you cannot look inside the pod to check: exec, attach, and
port-forward are denied there ([node-exec-mode.md](node-exec-mode.md)). The
workload's own logs show that wait finishing, and step 8 reports what CDS
decided.

## 5. Create and attach a volume

Volumes need `c8s install --volumes`, which deploys the `volumed` node agent
that opens them, and single-tenant nodes ([volumes.md](volumes.md)).

```sh
c8s volume create --name weights --source ./weights --out ./weights.img \
  --path /tenant-a/volumes/weights --escrow-out ./weights.escrow.json \
  --node <NODE> --mesh-ca mesh-ca.pem $PIN $KEY
```

Keep the escrow file: it and the CDS process hold the only copies of the
volume's key, and a CDS restart drops the stored one
([operator.md](operator.md#cds-is-a-singleton)). A run that builds the image but
cannot store the key leaves both files and says so; store the key with
`c8s secrets put <path> --from-file <escrow>`, since `--out` refuses a second
build.

`create` prints the grant and the `data` mount rule for step 6, plus what the
pod needs:

```yaml
annotations:
  confidential.ai/c8s-volumes: "weights=/tenant-a/volumes/weights"
nodeSelector:
  kubernetes.io/hostname: <NODE>
```

The `nodeSelector` is not optional: the device is on the one node you attach it
to.

Attaching runs outside the cluster — on the hypervisor host, or as root on the
node — and the image is ciphertext, so copy it where the hypervisor can read it.
Which option applies to your nodes, and why, is in
[volumes.md](volumes.md#attaching-the-image).

A. Cold-plug at VM launch: add these to the VM's launch command, image path on
the hypervisor host.

```sh
-drive if=none,id=volweights,file=/srv/c8s/weights.img,format=raw \
-device virtio-blk-pci,drive=volweights,serial=c8s-vol-weights
```

B. Hot-attach from the QEMU monitor of a VM that was launched with a
virtio-scsi controller (`-device virtio-scsi-pci,id=scsi0`).

```text
drive_add 0 if=none,id=volweights,file=/srv/c8s/weights.img,format=raw
device_add scsi-hd,id=weights,bus=scsi0.0,drive=volweights,serial=c8s-vol-weights
```

C. Build a local SCSI disk through LIO, as root on the node holding the image.

```sh
c8s volume attach weights --image /srv/c8s/weights.img
```

Nothing confirms the key until a pod runs; the plaintext then appears at
`/mnt/c8s-data/c8s-volumes/weights`.

## 6. Grant the paths in the entry

A secret or volume key reaches a pod only if its containers match an entry
granting the path, so re-derive the entry with the grants and the sidecar
mounts. `mounts.json` maps container name to mount policy:

```json
{"<CONTAINER>": {"policy": "exact", "rules": [
  {"destination": "/run/c8s/secrets", "kind": "emptyDir"},
  {"destination": "/mnt/c8s-data/c8s-volumes/weights", "kind": "data"}
]}}
```

```sh
kubectl -n <NAMESPACE> get deploy <NAME> -o json |
  c8s allowlist derive <ENTRY> - --env any --mounts-file mounts.json \
    --secret-read /tenant-a/db --secret-read /tenant-a/volumes/weights > entry.json
c8s allowlist apply entry.json $PIN $KEY
```

Name each path exactly: a subtree grant covers every secret and volume beneath
it, and the annotation picking one is host-written.

## 7. Publish a route

The router serves only the hosts and paths the operator-signed route manifest
names ([operator.md](operator.md#route-manifest)):

```sh
c8s routes add --host api.example.com --path / --workload <ENTRY> \
  --address c8s-<ENTRY>.<NAMESPACE>.svc.cluster.local:<PORT> \
  --operator-keys c8s-operator-pub.pem $PIN $KEY
```

`<PORT>` is the port the workload itself listens on, not a C8s port. `--new`
starts the first manifest of a cluster; without it `add` refuses an empty store.
`--operator-keys` is required because the write re-signs every stored route.
`--workload` is the entry name the backend's certificate must carry, so the
router handshakes with the pod's mesh endpoint and answers 502 rather than reach
it in the clear. That certificate must also carry the same allowlist digest as
the router's own, so after an allowlist write the route refuses requests — 502
while the backend lags, 503 while the router does — until both have renewed
([operator.md](operator.md#route-manifest)). Which manifest the router applied
is evidence a client can check:
[routes-evidence.md](routes-evidence.md).

## 8. Confirm, or find out why not

`kubectl -n <NAMESPACE> get pods` shows the pod running. A pod that runs but
never gets its secret or volume was refused by CDS, and only CDS can say why —
the container set it compared is invisible to the pod:

```sh
c8s secrets explain --sandbox <SANDBOX_ID> $PIN $KEY
```

`explain` reports what the node's inventory says the pod runs, how each entry
measures against it, and which entry and grant resolved. `<SANDBOX_ID>` names
one pod run; `c8s verify` prints it ([verify.md](verify.md)).
