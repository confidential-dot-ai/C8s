# Allowlist helpers

Source: [templates/_allowlist.tpl](../../templates/_allowlist.tpl).
[All helpers](../README.md).

`c8s.components` resolves `Values.c8sComponents` into a JSON list of
`{name, image, enabled, cdsExempt, argvPinned}` records. `valuePath` selects the image object;
`enabledPath` selects its boolean gate, with an empty path enabling the component.
The derived name is the component's `valuePath`. `c8s.valueAtPath` takes
`(dict "root" <dict> "path" "a.b.c")` and returns the resolved value as JSON.
Boolean gates compare that JSON text to `true`: Helm's `fromJson` expects an
object, so scalar booleans must be handled as text here.

The component inventory drives both allowlist derivation and the coverage guard
in [validations.yaml](../../templates/validations.yaml); `c8s install` also reads
it from chart values. CDS is exempt from that guard because its self-entry is
seeded independently. Components marked `argvPinned` are covered by argv-pinned
seed entries and excluded from any-argv derivation.

`c8s.imageAllowlist` returns a digest-to-image-reference map containing enabled,
digest-pinned components when `bootstrapAllowlist.deriveComponents` is true,
plus the CDS self-entry and enabled router nginx. Nginx is independently versioned
and derives from its own image values. Argv-pinned components and RKE2
containerd-prep images are seeded through `c8s.argvPinnedEntries`.
With `node.baked=true`, the same derivation covers the operator/get-cert,
CDS, mesh and nginx images rendered into the measured guest. The host stages
this seed merged with signed workload entries for CDS; the image also admits
the core images in its NRI bootstrap floor. The local-path helper remains
argv-pinned in the seed for baked nodes.

`c8s.anyArgvDigests` extracts workload digests whose command, args, environment,
and mount policies are all unconstrained. An omitted mount policy is `deny`
and prevents inclusion. `c8s.baseWorkloads` renders these, merged with
`c8s.imageAllowlist`, as any-argv workload entries for the host plugin's boot
base, excluding `c8s.argvPinnedDigests`. Workloads that pin any of those fields remain in the served
seed without being added by `c8s.anyArgvDigests`.

`c8s.digestWorkloadName` takes `digest` and `image`, strips the image reference
to its final repository segment, truncates it to 50 characters, substitutes
`image` for an invalid name, and appends the first 12 lowercase digest hex digits.
Keep this naming rule aligned with `pkg/allowlist.DigestEntryName`.

`c8s.allowlistSeedJSON` emits `c8s.allowlist/v1`: one workload per derived image
digest outside `c8s.argvPinnedDigests`, with command, args, environment, and mount
policies set to `any`, followed by `c8s.argvPinnedEntries`, the
[router entry](#router-entry) and `bootstrapAllowlist.workloads`.
A supplied workload replaces the entire derived entry of the same name. The document must satisfy `pkg/allowlist.ParseJSON`.

## Argv-pinned entries

`c8s.argvPinnedEntries` takes the chart context and returns a JSON map of
entry names to workload policies for these platform images:

| Image/use | Included when | Pinned invocation |
|---|---|---|
| NRI installer | `nriImagePolicy.enabled` | Install script (pins script when baked), optional uninstall script, `sleep infinity`, and the `c8s uninstall` host-sweep script with its `/bin/sleep 2147483647` pause |
| NRI containerd-prep | NRI enabled, RKE2, and not baked | Containerd-prep script |
| Local-path helper | `attestationApi.cvmMode=bare-metal`, helper digest configured | `/bin/sh /script/setup` or `/bin/sh /script/teardown`; args accept per-PVC flags |

Script argv comes from the same includes/files as the DaemonSets. Trailing
newlines collapse to one, matching YAML block-scalar clipping. Image
references are digest-pinned.

Install, uninstall, containerd-prep, and local-path helper entries explicitly
set `mounts: {policy: any}` because these platform scripts require host mounts,
which exact workload mount rules do not support. Their command/args pins still
apply. The pause container has no workload mounts and retains the default
`deny` policy. Operator-supplied workload policies are preserved as authored.

Names use `c8s.digestWorkloadName`. `c8s.allowlistSeedJSON` excludes these
digests from its any-argv derivations, adds the pinned entries, then applies
same-named `bootstrapAllowlist.workloads` overrides. An image bump produces
a new entry name for additive seeding.

`c8s.argvPinnedDigests` derives its matching digest set from values alone:
calling `argvPinnedEntries` there would recurse through the install script's
boot config. Keep the inclusion conditions of both helpers aligned.

[pinned_seed_test.go](../../../pinned_seed_test.go) checks rendered invocations and mounts,
rejection of different argv, and exclusion from the boot config's local base.
The operator-facing bootstrap behavior is described in
[Allowlist and capabilities](../../../../../docs/allowlist-and-capabilities.md#bootstrap).

## Router entry

The router pod's non-injected containers span two images, so no single-image
entry matches it. `c8s.routerWorkload` returns the entry that does, which the
seed names `c8s.routerWorkloadName`:

| Container | Declared as | Policy |
|---|---|---|
| nginx | main | `router.nginx.image.digest`, everything `any` |
| cds-attest | main, when `router.attest.enabled` | c8s image digest, command `/c8s`, args exactly `router.cdsAttestArgs` |
| allowlist-proxy | main, when `router.renderAllowlistRoute` | c8s image digest, command `/c8s`, args exactly `router.allowlistProxyArgs` |
| acme | init, when `router.acmeSidecar` | c8s image digest, command `/c8s`, args exactly `router.acmeArgs` |

The deployment renders its args from the same helpers in
[router-helpers.tpl](../../templates/router-helpers.tpl), so the pins cannot
drift. `/c8s` is the c8s image's entrypoint, which the pod spec does not
override. acme is a native sidecar: as a declared init container it is admitted
but not required. Mounts and environment stay `any`, as in the c8s image's own
any-argv entry; that entry is what lets get-cert be dropped as injected before
matching.

`c8s.routerWorkloadSeeded` returns `true` when the router is enabled,
`bootstrapAllowlist.deriveComponents` is true (it seeds the c8s image's
any-argv entry), both `router.nginx.image.digest` and `image.digest` are set,
at least one c8s-image main container renders, no pinned argument
contains `$`, and `router.attest.expectedWorkload` does not name an operator
router entry. Kubelet expands `$(VAR)` and `$$` in args, so such argv
(`$(HOST_IP)` in the attestation-api URL when `cvmMode=bare-metal` without a
local attestation-api) is not known at render time. `c8s.routerArgv` takes
`(dict "root" $ "expectedWorkload" <name>)` and returns the rendered argv per
container name; `c8s.routerEntry` takes the same and returns the entry.

An operator router entry is a `bootstrapAllowlist.workloads` entry listing both
`router.nginx.image.digest` and `image.digest` (`c8s.operatorRouterEntries`).
A gate naming one replaces the seeded entry. `c8s.routerWorkload` fails the
render when the router pod would match more than one entry, seeded or operator,
or when the gate names a `bootstrapAllowlist.workloads` entry that is not an
operator router entry: either way the leaf never carries the gated name.

`c8s.routerWorkloadName` is `c8s-router-` followed by the first 12 hex digits of
the SHA-256 of the rendered entry, so a changed digest or argv yields a new name.
CDS seeds additively by name, so the new entry lands beside the old one, as with
the digest-named entries. A gate naming this entry, defaulted or an explicit
`c8s-router-*` value, sits inside its own cds-attest argv, so the hash takes
that `--expected-workload` as a fixed placeholder; freezing the rendered default
keeps the name, and an explicit `c8s-router-*` value that differs from it fails
the render. Any other explicit gate is hashed as written.

`router.expectedWorkload` defaults the cds-attest readiness gate to
`c8s.routerWorkloadName` when `router.defaultGate` holds: the gate is unset, the
entry is seeded, `router.attest.enabled` is true, `router.hostPort.enabled` is
false, and the inventory is reachable. An explicit string, including `""`, wins;
any other non-null value fails the render.
The seeded cds-attest argv includes the resulting `--expected-workload`.

[router_entry_test.go](../../../router_entry_test.go) feeds the rendered router,
CDS, operator and mesh pods through `secrets.WorkloadContainers` and
`MatchWorkload`.
