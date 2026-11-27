# A cloud cluster's Trust Authority (TA)

The TA — the VM outside the cluster that
holds C8s policy and signs every workload certificate — does not run on the
cloud that runs the cluster. This page covers where it runs instead, the flows
it needs, and where the node pins come from on AKS and GKE. What the TA does for a
cluster is [operator.md](operator.md); running several of them is
[ta-ha.md](ta-ha.md).

## Where it runs

`ta-pin.json` binds the guest image identity and the exact launch-file bytes.
The image identity is the SEV-SNP launch measurement or the TDX tuple of
MRTD, RTMR[1] and RTMR[2]. For `ta-guest`, use the image measurements from its
published `manifest.json` and the exact `ta-config.yaml`
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

Kata SEV-SNP binds the SHA-256 of its whole initdata document to `HOST_DATA`.
Kata TDX binds the SHA-384 of the same whole document to `MRCONFIGID`, and the
document must then declare `algorithm = "sha384"` (`"sha256"` is the SEV-SNP
form). On TDX the TA starts in one of two cases:

- RTMR[3] holds the file's seed, as the `ta-guest` initrd extends it.
  `MRCONFIGID` is then not read.
- `MRCONFIGID` holds the file's SHA-384 and RTMR[3] is all zero.

It refuses every other report. The `MRCONFIGID` case is not specific to Kata:
any TDX launcher that sets the field, for a guest that extends nothing into
RTMR[3], starts the TA, and no register shows that an initrd staged the
operator key. The TA accepts the field because the check asks only what its
own verified report proves about the file, and either field proves it byte
for byte. One check serves every guest: it cannot tell a `ta-guest` VM from
another, so identify the TDX image with pins on MRTD, RTMR[1] and RTMR[2].
The operator keys sit in the document's `ta-config.yaml` entry, so the
whole-document digest binds them too. What the `MRCONFIGID` case does not
show is which code read them: the image pins establish the image.
`c8s verify` can also display `MRCONFIGID`. HA peer and generated Genesis
pins still bind RTMR[3], so they cannot authenticate an MRCONFIGID-only TA.

For an MRCONFIGID-only TDX deployment with one replica filling one voter seat,
follow the [runbook's `--alone` warning](ta-ha-runbooks.md#1-start-a-cluster-genesis).
Use `--platform tdx --image-manifest <manifest.json>` and omit `--vcpus`;
the manifest must contain your Kata guest's MRTD, RTMR[1] and RTMR[2].
`genesis --alone` still authenticates the target: pass a separate schema 3
`--ta-pin` with MRTD, RTMR[1], RTMR[2], the full `launch_file`, and
`"launch_file_field": "init_data"`. Also pin RTMR[3] to all zero (`""` in the
`rtmr` array): every Trust Authority pin that reads `MRCONFIGID` must, and is
refused otherwise, so the target cannot use a different RTMR[3]-bound launch
file.
`--alone` allows a one-voter Genesis without a peer response; the decree's
generated RTMR[3] pins still do not match that target.

The cloud chart rejects schema 3 pins. A schema 2 TDX pin can pass rendering
but fail TA authentication; install may warn and apply a release whose
clients cannot authenticate their TA.

Supply the TA container and an attestation API on guest loopback
(`--attestation-api-url`). The guest launch digest does not cover containers
loaded after launch: the [agent policy](#the-agent-policy) in the initdata
document is what holds the guest to the TA's containers. C8s provides no
measured Kata TA image or integration tests for this deployment, including
replicated TAs.

Put the TA configuration in the initdata document as follows (schematic, the
SEV-SNP form; on TDX write `algorithm = "sha384"`):

```toml
version = "0.1.0"
algorithm = "sha256"

[data]
"ta-config.yaml" = '''
schemaVersion: c8s-ta/v1
...
'''
"policy.rego" = '''
package agent_policy
...
'''
```

C8s detects initdata by its TOML `data` table and requires a supported
`algorithm`, a string `ta-config.yaml` entry and a string `policy.rego` entry
that declares `package agent_policy`; other files are read as bare YAML
configuration. The TA refuses to start from a document without the policy,
and every command refuses a pin that embeds one. Other initdata keys are
bound and not read.

Pass the whole document to the runtime and mount identical bytes for
`c8s ta --config`; even changes to comments or whitespace break the binding.
Use it for every command's `--config` and every TA pin's `launch_file`.
Kata does not use the [`ta-guest` image's staging](../images/ta-guest/README.md#launch-requirements).
On either platform the document must be at most 1 MiB; keep it well below that so its JSON-encoded
pin also fits the release ConfigMap's 1 MiB limit.

#### The agent policy

The Kata guest agent evaluates `policy.rego` on every request the host makes
of it. The launch binding covers the whole document, so a pin that embeds the
document fixes the policy too. C8s requires the entry and does not judge its
rules: whoever writes the pin answers for them. The policy must at least:

- allow a container only from the TA and attester images, each named by
  digest. With images pulled inside the guest, the rules that Kata's
  `genpolicy` generates for 3.30 do not check the image a container is pulled
  from, so add that rule. Tell the sandbox container apart by the
  `io.kubernetes.cri.container-type` entry in the `image_guest_pull` storage's
  driver options, which is the field the agent reads, not by an annotation;
- fix each container's arguments, environment and mounts. The TA's
  `--attestation-api-url` and `--config` are arguments, and a host that could
  change them would choose the attester the TA asks about itself;
- refuse `ExecProcessRequest`, `SetPolicyRequest` and writes to a container's
  input.

`genpolicy` 3.30 output fixes those and denies those requests by default.
Its settings need matching to the
cluster before the policy admits the pod: the OCI version the runtime sends,
the container runtime's state directory, the guest-pull paths and
`confidential_guest`. A refused request's error, in the pod's events, carries
the policy's trace of the request it judged.

A policy that denies `ReadStreamRequest` also denies `kubectl logs`. A
privileged container makes the runtime mount the sandbox's `/sys` writable,
which generated policies refuse: give the attester the one capability it
needs instead.

A policy generated from a bare Pod names that pod and its namespace. HA
replicas share one launch file byte for byte, so they share one policy: C8s
has not established a policy that admits each replica of a set.

**Upgrading.** A TA already launched on a document with no `policy.rego`
does not start on this release, and its pins are refused. Adding the entry
changes the launch digest, so write the new document, pin it, and launch the
TA again on it before upgrading the clients.

`c8s ta config new` produces bare YAML and a pin for it. For Kata, write a
schema 2 SEV-SNP [measurements config](measurements.md#the-measurements-config)
for `c8s install --ta-pin` instead:

- Set `measurement` to your Kata guest's launch digest, established from your
  own build at the deployed vCPU count. The `ta-guest` image's digest will not match.
- Set every entry's `launch_file` to the same whole initdata document as a
  JSON string. Omit `launch_file_digest` and `approver_key`.

Replace the placeholders below with those values. This example is for SEV-SNP;
a TDX pin using the file's RTMR[3] seed does not match an MRCONFIGID-only TA.

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

For HA commands taking `--image-manifest`, supply a manifest with your Kata
guest's image measurements. The pin builders check the initdata algorithm
against `--platform`; TA startup checks it against the attested family.

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
