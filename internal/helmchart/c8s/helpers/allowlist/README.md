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
policies set to `any`, followed by `c8s.argvPinnedEntries` and `bootstrapAllowlist.workloads`.
A digest of the mesh repository is the exception: its entry pins the command, the
arguments and the credential mount of the measured base's mesh entry
([image-policy.yaml.in](../../../../../node-guest-image/c8s/image-policy.yaml.in)),
which is the container the injector builds; its environment stays `any`.
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
