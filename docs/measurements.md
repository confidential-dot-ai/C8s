# Measurements

What a C8s node commits to its hardware evidence, where each value lands, and
the measurements config that pins them. A measurement pin is a value a verifier
requires before it trusts an endpoint: `c8s verify` enforces the pins you give
it, and so does armTLS, the mutual TLS C8s components authenticate each other
with, inside the cluster ([verify.md](verify.md), [armtls.md](armtls.md)).

Every C8s node is a confidential VM (CVM) and its pods are processes inside it,
so every value here belongs to the node. `--hardware-platform` decides which
set applies and `--cvm-mode` where the evidence comes from
([overview.md](overview.md#cvm-modes-and-hardware-platforms)). `‖` below is
byte concatenation.

## AMD SEV-SNP

| Report field | Holds | Pinned with |
|---|---|---|
| `MEASUREMENT` | The launch digest: SHA-384 over the guest's initial memory and vCPU state. | `--measurements`, config `measurement` |
| `HOST_DATA` | 32 bytes the launcher commits at launch. On a measured node image, SHA-256 of the launch key's exact PEM bytes; all zero when a guest is launched for no key. | `c8s verify --init-data`, config `approver_key` |
| `REPORT_DATA` | 64 bytes the guest chooses: `SHA-384(PKIX-DER(pubkey) ‖ challenge)`, zero-padded. The challenge slot is empty outside an issuance. | Derived by the verifier from the peer's key; `--expected-report-data` sets it for a saved evidence file |

The launch digest covers the initial state of every vCPU, so one image build
yields one digest per vCPU count: pin the count the VM runs at. A guest cannot
extend anything after launch here, so the report describes boot state only and
there is no policy history on this platform. It also carries the debug flag and
the TCB versions, which `c8s verify --allow-debug` and `--min-tcb-*` judge.

## Intel TDX

TDX measures the firmware into one launch register, MRTD, and exposes four
runtime measurement registers, RTMR[0] to RTMR[3], extendable in the guest.

| Register | Holds | Pinned with |
|---|---|---|
| `MRTD` | The launch digest: the TDX virtual firmware (TDVF) alone. | `--measurements`, config `mrtd` |
| `RTMR[0]` | TD HOB and VMM ACPI tables. It varies with the VM's vCPU and memory shape, so nothing pins it. | — |
| `RTMR[1]` | The guest kernel. | `--rtmr 1=<HEX>`, `--image-manifest`, config `rtmr[1]` |
| `RTMR[2]` | The kernel command line, which carries the dm-verity root hash of the read-only root. | `--rtmr 2=<HEX>`, `--image-manifest`, config `rtmr[2]` |
| `RTMR[3]` | The launch key the node was started for, then any workload images a measurer extended, then the allowlist policies it applied. | `--rtmr 3=<HEX>` or `--operator-pkey`, both needing `--image-manifest`; `--pin-policy` or `--trust-operator` then judge the replayed policies |
| `REPORTDATA` | As SEV-SNP's `REPORT_DATA`. | Derived by the verifier |

Pinning MRTD alone leaves the guest unpinned: it covers the firmware, so a host
can boot another kernel under it. `--image-manifest` pins MRTD, RTMR[1] and
RTMR[2] from one build.

### Policy history

RTMR[3] is extended by software inside the guest, so on its own it says nothing
about which image booted: pin it only together with an image, which is why
`--rtmr 3=` and `--operator-pkey` both require `--image-manifest`. The register
holds a chain: the seed the measured initrd extends from the node's launch key,
then one event per image a node's workload measurer extended, in first-extend
order (`c8s get-kubeconfig --workload-image` names them; the C8s node image
runs no such measurer), then one per allowlist policy the node applied.

```text
seed      = SHA-384( 0x00 * 48 ‖ SHA-384(launch key PEM bytes) )
extend(d) = SHA-384( register ‖ SHA-384("sha256:<hex>") )
```

Policies are measured only on TDX and only where the node plugin has
`measure_policies` on: the chart value `nriImagePolicy.measurePolicies`, which
the chart refuses unless it also deploys the node's attestation-api, so not on
the lane that bakes it. The measurer seeds its journal from the staged launch
key, so a node without one applies no pulled allowlist while the setting is on
([allowlist-and-capabilities.md](allowlist-and-capabilities.md#measured-policy-history)).

Each policy digest is SHA-256 of the exact allowlist bytes served by CDS, the
Certificate Distribution Service that holds the cluster's policy and signs its
workload certificates — the same value a leaf's matched-workload extension
carries ([certificate-extensions.md](certificate-extensions.md)). The node
journals a digest before extending it, so a reader's list may run ahead of a
quote but never lags it, and each digest is extended at most once and at most
256 times per boot; past that cap the node keeps the policy it has.

Evidence carries the list for replay: as `runtimeExtensions` in the armTLS
attestation extension, and as `measured_policies` in the bundle from attest-pq
or attest-lb, the router's two attested handshakes
([routes-evidence.md](routes-evidence.md)). `c8s verify --operator-pkey`
derives the seed, replays the list and reports the longest prefix the register
proves; `--pin-policy` or `--trust-operator` then judge the policies. Without
one of those, a non-empty history leaves the verdict partial: the register is
accounted for, the policies are not ([verify.md](verify.md)).

## Where the evidence comes from

- **`bare-metal`, `gke`**: the node's own report interface, so the fields above
  are the silicon's own. On SEV-SNP that is the guest device `/dev/sev-guest`;
  on TDX it is the kernel's ConfigFS TSM report interface
  (`/sys/kernel/config/tsm/report`), which gets a quote through the host's
  Quote Generation Service.
- **`aks`**: the Azure vTPM at `/dev/tpm0`, whose report wraps an SEV-SNP
  report (`az-snp`) or a TD quote (`az-tdx`); `--hardware-platform` selects
  which shape the node asks for. The freshness binding is the vTPM quote nonce,
  compared with the 48 bytes C8s sends rather than the padded hardware field,
  and `--init-data` pins vTPM PCR[8] rather than `HOST_DATA`. C8s pins no other
  PCR.

The launch-key binding is `bare-metal` only: only the measured node image
commits a launch key, and on the managed lanes the cloud's own stack owns the
field or register that would carry it. So `c8s node launch-config` and
`c8s get-kubeconfig` are `bare-metal` commands
([launch-configuration.md](launch-configuration.md)).

## The measurements config

A measurements config pins whole images: each entry is one image matched as a
tuple, so a digest from one build cannot be paired with registers from another.
Every component that dials a pinned CDS takes it as `--image-policy-file`:
`c8s verify`, the client commands (`c8s cds`, `c8s allowlist`, `c8s secrets`,
`c8s routes`, `c8s volume`), `c8s install`, CDS itself, and the sidecars C8s
injects — among them get-cert, which fetches a pod's certificate. Some also
accept `--image-policy-json`, the same document inline; `c8s get-kubeconfig`
pins its node with `--image-manifest`.

```json
{
  "schema_version": "1",
  "tee": "tdx",
  "measurements": [
    {
      "name": "rke2-tdx",
      "mrtd": "<96_HEX>",
      "rtmr": [null, "<96_HEX>", "<96_HEX>", null]
    }
  ]
}
```

| Field | Rule |
|---|---|
| `schema_version` | Exactly `"1"`. |
| `tee` | The TEE family: `sev-snp` or `tdx`, which is what `derive` writes. A platform tag such as `snp` or `az-tdx` normalizes to its family. One file covers one family. |
| `measurements` | At least one entry. Two entries may not pin the same tuple. |
| `name` | Required, unique in the file, and diagnostic only: nothing matches on it. |
| `measurement` | SEV-SNP only and required there: the launch digest, 96 lowercase hex. |
| `mrtd` | TDX only and required there, 96 lowercase hex. |
| `rtmr` | TDX only: up to four slots, `rtmr[0]` must be `null`, a null slot is unpinned, `""` pins the all-zero register. |
| `approver_key` | Optional: the launch key, PEM. The entry then also requires that this guest was launched for that key — the RTMR[3] seed on TDX, `HOST_DATA` on SEV-SNP — which only a measured node image on `bare-metal` carries. |

Unknown fields, repeated JSON keys, trailing data and an empty `measurements`
list are refused; omit the flag to pin nothing.

`c8s install --image-policy-file` also refuses an `approver_key` entry and
per-image register differences: the chart carries one digest list and one
register map to every in-cluster verifier. CDS renders the set it enforces at
`/measurements`, which `c8s verify --kind cds` compares against your file. To
build a config from an image build, see
[verify.md](verify.md#derive-the-pins-yourself).
