# Allowlist helpers

Source: [templates/_allowlist.tpl](../../templates/_allowlist.tpl).
[All helpers](../README.md).

`c8s.components` resolves `Values.c8sComponents` into a JSON list of
`{name, image, enabled, cdsExempt, argvPinned, entrypoint, denyBelow}` records. `valuePath` selects the image object;
`enabledPath` selects its boolean gate, with an empty path enabling the component;
`entrypoint` is the argv prefix every container running the image starts with;
`denyBelow` lists the image paths no pod volume may cover.
The derived name is the component's `valuePath`. `c8s.valueAtPath` takes
`(dict "root" <dict> "path" "a.b.c")` and returns the resolved value as JSON.
Boolean gates compare that JSON text to `true`: Helm's `fromJson` expects an
object, so scalar booleans must be handled as text here.

The component inventory drives both allowlist derivation and the coverage guard
in [validations.yaml](../../templates/validations.yaml); `c8s install` also reads
it from chart values. CDS is exempt from that guard because its self-entry is
seeded independently. Components marked `argvPinned` are covered by argv-pinned
seed entries and excluded from any-argv derivation.

`c8s.imageAllowlist` returns a digest-to-`{image, entrypoint, mounts}` map containing enabled,
digest-pinned components when `bootstrapAllowlist.deriveComponents` is true,
plus the CDS self-entry and enabled router nginx. Nginx is independently versioned
and derives from its own image values (`router.nginx.entrypoint`,
`router.nginx.denyBelow`). A derived component without an entrypoint or a
`denyBelow` list fails the render. `c8s.componentMounts` builds the
component's `confined` mount policy: its `denyBelow` list, and as
`unconfined` the destinations where the chart mounts a writable host path, a
PVC or a ConfigMap for that image, computed from the values that place them.
Keep those lists in step with the component templates;
[pinned_seed_test.go](../../../pinned_seed_test.go) checks every rendered
mount against them, classifying ConfigMaps and PVCs as unprotected storage.
`c8s.componentContainer` renders one such image as an allowlist container:
`command` exact at the entrypoint, `args` any, the entry's `mounts`, and `env`
any when asked for (the seed; the base leaves it absent). Argv-pinned components and RKE2
containerd-prep images are seeded through `c8s.argvPinnedEntries`.
With `node.baked=true`, the same derivation covers the operator/get-cert,
CDS, mesh and nginx images rendered into the measured guest. The host stages
this seed merged with signed workload entries for CDS; the image also admits
the core images in its NRI bootstrap floor. The local-path helper remains
argv-pinned in the seed for baked nodes.

`c8s.openArgsEntries` extracts workload digests whose args and environment
policies are unconstrained, whose mount policy is `any` or `confined`, and
whose command is `any` or `exact`, as digest-to-`{image, entrypoint, mounts}`
with an empty entrypoint for `any`. An omitted mount policy is `deny` and
prevents inclusion; of two entries for one digest, `any` mounts win over
`confined`, and two different `confined` policies fail the render. `c8s.baseWorkloads` renders the
host plugin's boot base, excluding `c8s.argvPinnedDigests`: each
`c8s.imageAllowlist` image as a `c8s.componentContainer` entry, and each
`c8s.openArgsEntries` digest under the command it pins or under any
(`c8s.openArgsContainer`). For a system image an operator also wrote an
open-args entry for, a wider operator pin (any, or a prefix of the
entrypoint) replaces the component's container and a different one is
admitted beside it. Workloads that pin args or env, or set mounts to `deny`
or `exact`, remain in the served seed without reaching the base.

`c8s.digestWorkloadName` takes `digest` and `image`, strips the image reference
to its final repository segment, truncates it to 50 characters, substitutes
`image` for an invalid name, and appends the first 12 lowercase digest hex digits.
Keep this naming rule aligned with `pkg/allowlist.DigestEntryName`.

`c8s.allowlistSeedJSON` emits `c8s.allowlist/v1`: one `c8s.componentContainer` workload per
derived image digest outside `c8s.argvPinnedDigests`, followed by
`c8s.argvPinnedEntries` and `bootstrapAllowlist.workloads`. The volumed entry
also carries `c8s.volumedHookContainers`: the pre-delete teardown hook's
script and pause, pinned like the installer's scripts and seed-only like them.
A same-named `bootstrapAllowlist.workloads` override replaces the volumed
entry whole, hook containers included; an override must declare them too, or
the pre-delete hook is refused and the uninstall fails.
A supplied workload replaces the entire derived entry of the same name. The document must satisfy `pkg/allowlist.ParseJSON`.

## Argv-pinned entries

`c8s.argvPinnedEntries` takes the chart context and returns a JSON map of
entry names to workload policies for these platform images:

| Image/use | Included when | Pinned invocation |
|---|---|---|
| NRI installer | `nriImagePolicy.enabled` | Install script (pins script when baked), optional uninstall script, `sleep infinity`, the `plugin-ready` readiness endpoint (`nri-image-policy.pluginReadyScript`), and the `c8s uninstall` host-sweep script with its `/bin/sleep 2147483647` pause |
| NRI containerd-prep | NRI enabled, RKE2, and not baked | Containerd-prep script |
| Local-path helper | `attestationApi.cvmMode=bare-metal`, helper digest configured | `/bin/sh /script/setup` or `/bin/sh /script/teardown`; args accept per-PVC flags |

Script argv comes from the same includes/files as the DaemonSets. Trailing
newlines collapse to one, matching YAML block-scalar clipping. Image
references are digest-pinned.

Install, uninstall, containerd-prep, and local-path helper entries explicitly
set `mounts: {policy: any}` because these platform scripts require host mounts,
which exact workload mount rules do not support. Their command/args pins still
apply. The pause and `plugin-ready` containers have no workload mounts and
retain the default `deny` policy. `plugin-ready` runs under `/bin/sh -c`
because `c8s uninstall` takes the entry's one non-script shape as its sweep
pause. Operator-supplied workload policies are preserved as authored.

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
