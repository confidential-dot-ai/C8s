# Native TDX qualification

The storage backends and logical image-transition tests are platform independent.
The current native recovery proof uses AMD's derived-key interface. Intel TDX
must be qualified separately before claiming the same hardware custody guarantee.

`test/pilot/cds-sealed-recovery/hardware/tdx.py` launches one disposable native TDX
guest on a qualified compute worker. It reuses the existing ownership journal,
UID-precondition cleanup, foreground deletion, PV reclamation check and fleet
health observations. Placement checks the Cloud Host's TEE and Node UID as well
as Kubernetes labels. Control-plane placement is refused. The fixture creates
one root PVC, one public launch Secret, one population Pod, one ingress policy
and one manual-lifecycle VM; it creates no Service or public endpoint.

The probe reads the fixed `TDX_FEATURES0` field through `TDG.SYS.RD` and requests
two native quotes with independently generated nonces. The quote commits to the
nonce, raw module status, feature value and exact launch-file hash. The external
verifier checks Intel's chain, revocations and collateral, the build's complete
MRTD/RTMR[1]/RTMR[2] tuple and the exact launch's RTMR[3] binding. Neither observed
measurements nor host-provided feature values are accepted as reference pins.

A successful query with bit 12 clear means that this module does not advertise
native sealing. A nonzero module status means the query failed; it is not proof
that sealing is absent. A set bit is also insufficient to qualify durable key
recovery: derivation, restart, image policy and loss of the original host still
need their own proofs. The result always reports `native_sealing_qualified=false`,
`full_acceptance_passed=false` and `production_ready=false`.

## Guest-only diagnostic

The pinned Linux 6.18.60 guest has no user API for `TDG.SYS.RD`. The small
`hardware/tdx-features-linux-6.18.60.patch` adds a read-only attribute to that
guest's TDX driver. It invokes only leaf 11 with fixed field ID
`0x0a00000300000008`; no user-selected leaf, metadata write or key derivation is
exposed. The attributes contain no secret material. No host kernel, firmware,
TDX module, QGS service or shared Kubernetes configuration is changed.

The isolated builder checkout starts at confidential-os-builder
`133aeae5e006ee11a72b2a7200a9fb173a1c85ef`. For this diagnostic image only, append
the patch to the existing fingerprinted kernel patch input
`kernel/patches/0002-sev-guest-measurement-registers.patch`. Its hash therefore
invalidates the kernel cache and appears in the kernel/image provenance; do not
patch compiled output or relabel an existing kernel manifest. Retain the
complete builder diff with the result. This staging choice adds no production
builder API or kernel capability requirement.

Build the native Go probe with `CGO_ENABLED=0`, bake it at
`/usr/local/bin/cds-tdx-probe`, and build ConfOS with `--platform tdx --smp 2
--memory 4G --profile-dir <hardware/tdx-profile> --extra <probe-extra>` and the
independently pinned TDVF firmware. The profile masks console login, rescue
shells, SSH and the guest agent, disables cloud-init and powers off after 30
minutes. An external owner still performs and audits cleanup; guest expiry
alone does not delete PVCs or VMs.

Compile `hardware/render.go` from the pinned cloud/operator module and run the
runner with explicit `--image`, `--renderer`, `--probe`, `--tools-image`,
`--nodes`, kubeconfig/tool paths and a fresh private `--directory`. The tools
image must be digest pinned. The verifier's manifest is the independently built
artifact, not a guest-supplied manifest. Retain the journal for the `cleanup`
action if interrupted, then independently audit all recorded resource paths.

The capability probe is not a CDS load test or a proof of total-replica recovery
on TDX. It neither accepts a CA key nor derives a sealing key. An absent feature
does not justify weakening attestation, substituting a software key or changing
production hosts to make a test pass.

## References

- [Intel TDX ABI, 348551-006US](https://cdrdv2-public.intel.com/853289/intel-tdx-module-abi-spec-348551006.pdf), sections 5.5.7 and 5.5.13.
- [OpenVMM field and feature definitions](https://github.com/microsoft/openvmm/blob/0f8346b5113e09c4d154fb6c1fe0565723c88553/vm/x86/x86defs/src/tdx.rs).
- [OpenVMM read-only call implementation](https://github.com/microsoft/openvmm/blob/0f8346b5113e09c4d154fb6c1fe0565723c88553/vm/x86/tdcall/src/lib.rs).
