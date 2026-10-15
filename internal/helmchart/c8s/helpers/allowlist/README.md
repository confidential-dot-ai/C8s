# Allowlist helpers

Source: [templates/_allowlist.tpl](../../templates/_allowlist.tpl).
[All helpers](../README.md).

`c8s.components` resolves `Values.c8sComponents` into a JSON list of
`{name, image, enabled, cdsExempt, argvPinned, entrypoint}` records. `valuePath` selects the image object;
`enabledPath` selects its boolean gate, with an empty path enabling the component;
`entrypoint` is the argv prefix every container running the image starts with.
The derived name is the component's `valuePath`. `c8s.valueAtPath` takes
`(dict "root" <dict> "path" "a.b.c")` and returns the resolved value as JSON.
Boolean gates compare that JSON text to `true`: Helm's `fromJson` expects an
object, so scalar booleans must be handled as text here.

The component inventory drives both allowlist derivation and the coverage guard
in [validations.yaml](../../templates/validations.yaml); `c8s install` also reads
it from chart values. CDS is exempt from that guard because its self-entry is
seeded independently. Components marked `argvPinned` are covered by argv-pinned
seed entries and excluded from component derivation.

`c8s.imageAllowlist` returns a digest-to-`{image, entrypoint}` map containing enabled,
digest-pinned components when `bootstrapAllowlist.deriveComponents` is true,
plus the CDS self-entry and enabled router nginx. Nginx is independently versioned
and derives from its own image values (`router.nginx.entrypoint`). A derived
component without an entrypoint fails the render. `c8s.componentShapes` turns
each such image into its allowlist containers; see
[Component shapes](#component-shapes). Argv-pinned components and RKE2
containerd-prep images are seeded through `c8s.argvPinnedEntries`.
With `node.baked=true`, the same derivation covers the operator/get-cert,
CDS, mesh and nginx images rendered into the measured guest. The host stages
this seed merged with signed workload entries for CDS; the image also admits
the core images in its NRI bootstrap floor. The local-path helper remains
argv-pinned in the seed for baked nodes.

`c8s.openArgsEntries` extracts workload digests whose args, environment and
mount policies are unconstrained and whose command is `any` or `exact`, as
digest-to-`{image, entrypoint}` with an empty entrypoint for `any`. An omitted
mount policy is `deny` and prevents inclusion. `c8s.pinnedComponentEntries`
extracts the other operator containers whose command is `any` or `exact` for a
component digest, verbatim. `c8s.baseWorkloads` renders the host plugin's boot
base, excluding `c8s.argvPinnedDigests`: each `c8s.componentShapes` image with
its containers, each `c8s.openArgsEntries` digest under the command it pins or
under any (`c8s.openArgsContainer`), and each `c8s.pinnedComponentEntries`
container, all beside one another for a shared digest. Workloads that pin
args, env or mounts for any other digest remain in the served seed without
reaching the base. The coverage guard in
[validations.yaml](../../templates/validations.yaml) accepts either kind of
operator entry whose command is `any` or a prefix of the component's
entrypoint.


`c8s.digestWorkloadName` takes `digest` and `image`, strips the image reference
to its final repository segment, truncates it to 50 characters, substitutes
`image` for an invalid name, and appends the first 12 lowercase digest hex digits.
Keep this naming rule aligned with `pkg/allowlist.DigestEntryName`.

`c8s.allowlistSeedJSON` emits `c8s.allowlist/v1`: one workload per derived
image digest outside `c8s.argvPinnedDigests`, with that digest's
`c8s.componentShapes` containers and `env: any`, followed by
`c8s.argvPinnedEntries` and `bootstrapAllowlist.workloads`. The volumed entry
also carries the pre-delete teardown hook's script and pause. A same-named
`bootstrapAllowlist.workloads` override replaces an entry whole, hook
containers included; an override must declare them too, or the pre-delete hook
is refused and the uninstall fails.
A supplied workload replaces the entire derived entry of the same name. The document must satisfy `pkg/allowlist.ParseJSON`.

## Component shapes

`c8s.componentPods` renders the pod spec of every enabled component workload
(operator, CDS, attestation-api, armtls-mesh, volumed and its teardown hook,
router) through the same named templates the workloads use, and
`c8s.podShapes` turns each container whose image is a component digest into an
allowlist container:

- `command` is `exact` at the component's entrypoint when the argv starts with
  it, else at the container's own command; `args` is `exact` at the rest of the
  argv, or `deny` when there is none.
- The argv is what the kubelet hands the runtime (`c8s.kubeletExpand`): `$$`
  becomes `$`, and a reference to one of the container's own variables fails
  the render, since its value differs per node. Escape it as `$$(NAME)` and
  expand it in the binary, as the attestation-api URL does with `HOST_IP`.
- A container with neither command nor args fails the render: the image's CMD
  would run, which the chart cannot pin.
- `mounts` is `exact` at one rule per volume mount (`c8s.mountRules`): `host`
  with the hostPath `source` and `readOnly`, `emptyDir`, or `data` for a
  ConfigMap, Secret, projected, downward-API or PVC volume, which must sit
  under `/mnt/c8s-data/`. The node admits an `emptyDir` or `data` mount only on
  memory or encrypted storage, so the component templates use memory
  `emptyDir`s and project their ConfigMaps, which puts them on tmpfs. A `subPath`, an unclean path or another volume source
  fails the render. A hostPath under `/var/run` yields a second container with
  the source under `/run`, the path containerd resolves it to on most nodes.

`c8s.injectedShapes` adds the sidecars the webhook injects to the C8s image's
entry: `get-cert`, `probe-file`, `get-secret` and `get-volume`, each pinned to
its invocation with `args: any`, and one container per combination of the
optional discovery, reload-watch and inventory-socket mounts. The
destinations match the webhook's fixed ones (`internal/webhook`); the socket
rule's source is `nriImagePolicy.hostPaths.runtimeDir` verbatim, since the NRI
plugin adds that mount without symlink resolution.

`c8s.componentShapes` collects both per digest. Every component digest must
have a rendered container, or the render fails.
[component_mounts_test.go](../../../component_mounts_test.go) checks that the
seed and the base admit every rendered component container exactly as
rendered, and refuse it with one argument or mount more or one mount fewer, for
default, gke, bare-metal and baked renders.

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
digests from its component derivations, adds the pinned entries, then applies
same-named `bootstrapAllowlist.workloads` overrides. An image bump produces
a new entry name for additive seeding.

`c8s.argvPinnedDigests` derives its matching digest set from values alone:
calling `argvPinnedEntries` there would recurse through the install script's
boot config. Keep the inclusion conditions of both helpers aligned.

[pinned_seed_test.go](../../../pinned_seed_test.go) checks rendered invocations and mounts,
rejection of different argv, and exclusion from the boot config's local base.
The operator-facing bootstrap behavior is described in
[Allowlist and capabilities](../../../../../docs/allowlist-and-capabilities.md#bootstrap).
