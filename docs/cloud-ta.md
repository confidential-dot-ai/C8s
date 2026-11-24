# A cloud cluster's Trust Authority (TA)

The TA — the VM outside the cluster that
holds C8s policy and signs every workload certificate — does not run on the
cloud that runs the cluster. This page covers where it runs instead, the flows
it needs, and where the node pins come from on AKS and GKE. What the TA does for a
cluster is [operator.md](operator.md); running several of them is
[ta-ha.md](ta-ha.md).

## Where it runs

`ta-pin.json`, the document every client holds the TA to, binds two values:
the guest's launch digest and the exact bytes of the launch file it booted,
which on SEV-SNP the launcher commits as `HOST_DATA`. For the `ta-guest` image
those are the digest in the `manifest.json` published with it and the
`ta-config.yaml`
([launch requirements](../images/ta-guest/README.md#launch-requirements)).

An AKS or GKE confidential VM proves neither: its launch digest is the
provider's firmware layer, and `HOST_DATA` belongs to the cloud stack
([measurements.md](measurements.md#where-the-evidence-comes-from)). So the TA
VM runs on SEV-SNP or TDX hardware you hold, beside the cloud cluster rather
than in it — a host launching it under an IGVM-capable QEMU, or a KubeVirt VM
on a cluster of your own confidential hosts. The cloud cluster holds its
address and its pin, which `c8s install --ta-address <HOST>:<PORT> --ta-pin
ta-pin.json` carries into the release, and nothing else of it.

### Under a Kata Containers runtime

This form binds the TA's configuration and nothing more. A Kata guest starts
`c8s ta` and its attester as containers after launch, so the launch digest
does not cover them, and C8s does not build, measure or test a TA launched
this way. A pin written for such a guest does not by itself establish which
code answers: holding the guest to the TA's code, storage and attester is
yours to establish and review. You supply both the container that runs the TA
and the attestation API it reports through, and the pin names neither. It works on SEV-SNP only: on Intel TDX a Kata
runtime commits initdata to `MRCONFIGID`, which the TA does not read, so a TA
launched that way exits at its launch-binding check.

A Kata Containers SEV-SNP runtime binds a guest to an initdata document: TOML
whose SHA-256 it commits as `HOST_DATA`. The TA reads such a document as its
launch file when it carries the configuration as a `ta-config.yaml` entry and
declares `algorithm = "sha256"`:

```toml
version = "0.1.0"
algorithm = "sha256"

[data]
"ta-config.yaml" = '''
schemaVersion: c8s-ta/v1
...
'''
```

The TA reads `algorithm` and the `ta-config.yaml` entry and nothing else.
Every other key and entry, a policy included, is covered by the binding but
neither read nor enforced by C8s: only whatever else consumes the document
can enforce it, so do not rely on the runtime's guest policy unless you
establish it separately.

Which form a file takes is decided by its bytes alone, never by a flag. A
file that parses as TOML with a `data` table is an initdata document, and is
then refused unless it declares the platform's `algorithm` and carries the
entry as a string. Any other file is read as the configuration itself; the
configuration is YAML, which does not parse as TOML: a mapping line such
as `clusterID: x` is not TOML, so no configuration is taken for an initdata
document. The configuration has no top-level `algorithm` or `data` key, and
a file that does parse as TOML with a `data` table is refused unless its
`algorithm` is the family's.

The whole document, with its policy and the configuration inside it, must be
at most 1 MiB. A larger file is never read as an initdata document: it is
read as the configuration itself, and an initdata document is not one, so
the TA refuses it with an error naming that limit. Keep it to a few hundred KiB:
the pin below embeds it, the release stores the pin in a ConfigMap with a
1 MiB limit of its own, and a pin over that limit is refused by the API
server when `c8s install` applies it, not when the pin is read. The
[`ta-guest` image's staging](../images/ta-guest/README.md#launch-requirements),
an `opkeydata` disk read into `/run/confai/operator-pubkey` by its initrd,
does not serve this form: a Kata guest boots the runtime's own image and runs
no such initrd. You supply the container that runs `c8s ta` and name the path
yourself. `c8s ta` still takes its own report from an attestation API on a
loopback address inside the guest (`--attestation-api-url`), which that image
runs for you and a Kata guest does not: run one beside it. Pass the document to the
pod as the runtime's initdata and mount the same bytes for `c8s ta --config`:
the file must match what the runtime received byte for byte, the parts the TA
does not read included, or the TA exits saying it is not the document this VM
was launched with.
Copy the file; do not regenerate it. A difference in a comment or in
indentation alone changes the digest and fails the same way.
Every command that reads a launch file takes the whole document, and the
launch-file binding is over the whole document. So do the clients that read
their launch file from a pin and not a flag, on replicas, nodes and workers:
they take whatever `launch_file` the pin carries, so every `ta-pin.json` in
use must carry the initdata document, and none falls back to a bare
`ta-config.yaml`.

`c8s ta config new` writes neither this form nor a pin for it, whatever
manifest it is given, for two reasons. Its pin takes its launch digest from
`--image-manifest`, which the `ta-guest` image's manifest fills with a digest
no Kata guest has. And it always names the bare `ta-config.yaml` as
`launch_file`, which is not what a Kata guest is bound to.

Write the pin for `c8s install --ta-pin` yourself, as a schema 2 SEV-SNP
[measurements config](measurements.md#the-measurements-config):

1. Establish the launch digest of your Kata guest, at the vCPU count it runs
   with, from your own build. It is the entry's `measurement`.
2. Put the whole initdata document, byte for byte, in the entry's
   `launch_file`, as a JSON string.
3. Leave out `launch_file_digest` and `approver_key`. Each of the three names
   what `HOST_DATA` holds, and a Kata runtime fills it with the document's
   digest, so an entry copied from a `ta-guest` pin with its `approver_key`
   kept matches no Kata guest.

```json
{
  "schema_version": "2",
  "tee": "sev-snp",
  "measurements": [
    {
      "name": "ta-kata-snp",
      "measurement": "<96_HEX>",
      "launch_file": "<the initdata document>"
    }
  ]
}
```

Every entry of a TA pin must carry that same `launch_file`, so the set holds
TA entries only.

The `c8s ta ha` commands that take `--image-manifest` build their pins from it too, and pair its launch
digest with the launch file. Give them a manifest you write that carries your
Kata guest's launch digest: with the one published for `ta-guest` they sign a
decree no Kata replica matches. The `c8s ta ha` commands do not hold the
document's `algorithm` to a platform: the TA at startup, `c8s install
--ta-pin` and the clients do.

## The flows it needs

| From | To | Port | Why |
|---|---|---|---|
| Every confidential node, and the member pods on it | TA | TCP, the `--ta-address` port (8443 unless the VM was started on another `--port`) | certificate issuance, allowlist pulls, secret and volume-key release |
| TA | every node, at the node's own address | TCP 1019 | the admission inventory's identity and digests, read on every issuance ([armtls.md](armtls.md#sandbox-identity)) |
| The operator's workstation | TA | the `--ta-address` port | `c8s install`, allowlist, route and secret writes, `c8s ta verify` |
| the TA, every confidential node, and the operator's workstation | `kdsintf.amd.com`, `api.trustedservices.intel.com` | TCP 443 | the endorsement certificate for evidence that carries none, and revocation lists |
| TA | the KMS of `c8s ta config new --kms-url`, when set | that URL's port | Pod CVM secret release ([pod-secrets.md](pod-secrets.md)) |
| Each TA replica | the other replicas | TCP 8444 | the replicated log, HA only ([ta-ha.md](ta-ha.md#addresses)) |

The TA dialing a node on 1019 is the flow a cloud network breaks. Each sandbox
token names the node's own address and the TA dials that address, so the TA host
needs a route to the node subnet — peering, a VPN or an interconnect — and a
node reached only through NAT answers on an address no token names. The
address must also fall inside a `--node-cidr` of the TA configuration, a
bound that holds no pod address
([operator.md](operator.md#what-an-install-deploys) states that overlap rule
and how to read the AKS pod range).

The vendor-certificate flow is easy to miss on the cluster side: in-cluster
verification runs through the node's own attestation API, and a TA serving
certificate on SEV-SNP carries a bare report whose VCEK that API fetches from
AMD.

## Node pins on AKS and GKE

`c8s ta config new --node-pins` takes the measurements config pinning the node
launch identities the TA admits. For the C8s node image that file comes from the
image build's published manifest
([verify.md](verify.md#derive-the-pins-yourself)). Azure and Google build the
node image on the managed lanes and publish no manifest, so the value comes
from a confidential node of the pool the cluster will run on, read before the
TA configuration is written.

1. Serve the attestation API on one confidential node of each machine shape
   the pool runs. An installed cluster already runs it on every confidential
   node, as the chart's DaemonSet. Before the install, write this as
   `node-evidence.yaml` and apply it in the release namespace (`c8s-system`
   below), the one where the chart's `deny-host-namespaces` policy admits the
   privilege that opening a TEE device needs. The selector and devices are the
   platform values file's `confidentialNodeSelector` and
   `attestationApi.devices`: below is `values-aks-snp.yaml`, and on GKE the
   selector is `cloud.google.com/gke-confidential-nodes-instance-type: SEV_SNP`
   with `/dev/sev-guest` as the whole device list.

   ```yaml
   apiVersion: v1
   kind: ConfigMap
   metadata:
     name: node-evidence
   data:
     config.toml: |
       [server]
       bind = "127.0.0.1:8400"
       [attestation]
       enabled = true
   ---
   apiVersion: v1
   kind: Pod
   metadata:
     name: node-evidence
   spec:
     nodeSelector:
       kubernetes.azure.com/security-type: ConfidentialVM
     containers:
       - name: attestation-api
         image: ghcr.io/confidential-dot-ai/attestation-api@<DIGEST>
         command: [/attestation-api]
         args: [--config, /etc/attestation-api/config.toml]
         securityContext:
           privileged: true
         volumeMounts:
           - name: config
             mountPath: /etc/attestation-api
           - name: tpm
             mountPath: /dev/tpm0
           - name: tpmrm
             mountPath: /dev/tpmrm0
     volumes:
       - name: config
         configMap:
           name: node-evidence
       - name: tpm
         hostPath:
           path: /dev/tpm0
           type: CharDevice
       - name: tpmrm
         hostPath:
           path: /dev/tpmrm0
           type: CharDevice
   ```

   `<DIGEST>` is the release's own attestation-api image: the
   `attestationApi.image` entry's `pinnedDigest` in
   `charts/lib/files/components.yaml`.

2. Forward the API's port into its pod, which is where it binds:

   ```sh
   kubectl -n c8s-system apply -f node-evidence.yaml
   kubectl -n c8s-system wait --for=condition=Ready pod/node-evidence
   kubectl -n c8s-system port-forward pod/node-evidence 8400:8400 &
   PF=$!
   ```

   On an installed cluster, forward the DaemonSet pod of the node you are
   reading instead, with `NODE` holding that node's name:

   ```sh
   POD=$(kubectl -n c8s-system get pod -o name \
       -l app.kubernetes.io/component=attestation-api \
       --field-selector "spec.nodeName=$NODE")
   kubectl -n c8s-system port-forward "$POD" 8400:8400 &
   PF=$!
   ```

3. Take a nonce-bound report, read the launch measurement out of the verdict,
   and stop what step 1 started. `/attest` takes the nonce as base64
   `report_data` and answers the `{platform, evidence}` object `c8s verify
   --from-file` reads; 48 bytes is the anchor length C8s binds, which the AKS
   vTPM carries as its quote nonce:

   ```sh
   openssl rand 48 > nonce.bin
   curl -sS -X POST http://127.0.0.1:8400/attest \
       -H 'content-type: application/json' \
       -d "{\"report_data\":\"$(base64 -w0 nonce.bin)\"}" > node-evidence.json
   c8s verify --from-file node-evidence.json -o json \
       --expected-report-data "$(od -An -vtx1 nonce.bin | tr -d ' \n')"
   kill "$PF"
   kubectl -n c8s-system delete -f node-evidence.yaml
   ```

   `measurement` is the node's launch digest and `measurement_pinned` is
   false: this run reads a value rather than checking one.

4. Write the measurements config and pass it to `c8s ta config new
   --node-pins`. On `aks-tdx` the verdict's `measurement` is the MRTD: write
   it as `mrtd` with `tee` set to `tdx`, where it covers Azure's TDX firmware
   ([measurements.md](measurements.md#the-measurements-config)):

   ```json
   {
     "schema_version": "1",
     "tee": "sev-snp",
     "measurements": [
       { "name": "aks-snp-node", "measurement": "<96_HEX>" }
     ]
   }
   ```

What that pin is worth, and what it costs:

- On AKS the digest is Azure's firmware layer, so it proves an Azure
  confidential VM of that generation rather than which node image booted.
- On GKE it is the node's own SEV-SNP launch measurement of what GCE loaded at
  launch, and an SNP launch digest covers the initial state of every vCPU: a
  pool of several machine shapes contributes one entry per vCPU count.
- Either way the value is read from a running node, so the pin binds the
  cluster to what that node reported and to no build you can audit.
- A provider change that moves the digest stops issuance on the nodes that
  carry the new one, and re-pinning costs a new configuration, a new pin, a
  TA relaunch and `c8s install --ta-pin` again — for a replicated TA too,
  whose later `node-images` decrees take only entries that bind a launch
  ([ta-ha.md](ta-ha.md#the-node-images-the-cluster-certifies)).
