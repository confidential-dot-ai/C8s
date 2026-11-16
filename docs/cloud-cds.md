# A cloud cluster's CDS

CDS — the Certificate Distribution Service, the VM outside the cluster that
holds C8s policy and signs every workload certificate — does not run on the
cloud that runs the cluster. This page covers where it runs instead, the flows
it needs, and where the node pins come from on AKS and GKE. What CDS does for a
cluster is [operator.md](operator.md); running several of them is
[cds-ha.md](cds-ha.md).

## Where it runs

`cds-pin.json`, the document every client holds CDS to, binds two values: a
launch digest from the `manifest.json` published with the `cds-guest` image,
and the exact bytes of the `cds-config.yaml` the VM booted, which on SEV-SNP
the launcher commits as `HOST_DATA`
([launch requirements](../images/cds-guest/README.md#launch-requirements)).

An AKS or GKE confidential VM proves neither: its launch digest is the
provider's firmware layer, and `HOST_DATA` belongs to the cloud stack
([measurements.md](measurements.md#where-the-evidence-comes-from)). So the CDS
VM runs on SEV-SNP or TDX hardware you hold, beside the cloud cluster rather
than in it — a host launching it under an IGVM-capable QEMU, or a KubeVirt VM
on a cluster of your own confidential hosts. The cloud cluster holds its
address and its pin, which `c8s install --cds-address <HOST>:<PORT> --cds-pin
cds-pin.json` carries into the release, and nothing else of it.

## The flows it needs

| From | To | Port | Why |
|---|---|---|---|
| Every confidential node, and the member pods on it | CDS | TCP, the `--cds-address` port (8443 unless the VM was started on another `--port`) | certificate issuance, allowlist pulls, secret and volume-key release |
| CDS | every node, at the node's own address | TCP 1019 | the admission inventory's identity and digests, read on every issuance ([armtls.md](armtls.md#sandbox-identity)) |
| The operator's workstation | CDS | the `--cds-address` port | `c8s install`, allowlist, route and secret writes, `c8s cds verify` |
| CDS, every confidential node, and the operator's workstation | `kdsintf.amd.com`, `api.trustedservices.intel.com` | TCP 443 | the endorsement certificate for evidence that carries none, and revocation lists |
| CDS | the KMS of `c8s cds config new --kms-url`, when set | that URL's port | Pod CVM secret release ([pod-secrets.md](pod-secrets.md)) |
| Each CDS replica | the other replicas | TCP 8444 | the replicated log, HA only ([cds-ha.md](cds-ha.md#addresses)) |

CDS dialing a node on 1019 is the flow a cloud network breaks. Each sandbox
token names the node's own address and CDS dials that address, so the CDS host
needs a route to the node subnet — peering, a VPN or an interconnect — and a
node reached only through NAT answers on an address no token names. The
address must also fall inside a `--node-cidr` of the CDS configuration, a
bound that holds no pod address
([operator.md](operator.md#what-an-install-deploys) states that overlap rule
and how to read the AKS pod range).

The vendor-certificate flow is easy to miss on the cluster side: in-cluster
verification runs through the node's own attestation API, and a CDS serving
certificate on SEV-SNP carries a bare report whose VCEK that API fetches from
AMD.

## Node pins on AKS and GKE

`c8s cds config new --node-pins` takes the measurements config pinning the node
launch identities CDS admits. For the C8s node image that file comes from the
image build's published manifest
([verify.md](verify.md#derive-the-pins-yourself)). Azure and Google build the
node image on the managed lanes and publish no manifest, so the value comes
from a confidential node of the pool the cluster will run on, read before the
CDS configuration is written.

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

4. Write the measurements config and pass it to `c8s cds config new
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
  CDS relaunch and `c8s install --cds-pin` again — for a replicated CDS too,
  whose later `node-images` decrees take only entries that bind a launch
  ([cds-ha.md](cds-ha.md#the-node-images-the-cluster-certifies)).
