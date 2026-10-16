# Allowlist helpers

Source: [templates/_allowlist.tpl](../../templates/_allowlist.tpl).
[All helpers](../README.md).

`c8s.components` resolves `Values.c8sComponents` into a JSON list of
`{name, image, enabled, cdsExempt, argvPinned, entrypoint}` records. `valuePath` selects the image object;
`enabledPath` selects its boolean gate, with an empty path enabling the component;
`entrypoint` is the argv prefix every container running the image starts with.
`c8s.entrypoint` takes `(dict "root" $ "valuePath" "cds.image")` and returns
that entrypoint as JSON; each component container renders it as its
`command`, so the argv never depends on the image's ENTRYPOINT or CMD.
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
container. The component shapes keep their own entry, named as in the seed;
the operator's containers for a digest share one named
`c8s.digestWorkloadName`, so each entry's per-variable evidence budget counts
only its own containers. Workloads that pin
args, env or mounts for any other digest remain in the served seed without
reaching the base. With `deriveComponents` off, the coverage guard in
[validations.yaml](../../templates/validations.yaml) requires every container
the chart runs a component's executable in to be admitted by an operator
entry: `c8s.admitsShape` checks the entry's command, args and mount rules
against the container's derived shape, and its env: `any`, or a `match` over
the shape's names whose `exact` matchers pin the values the shape pins. An
entry pinned to a component executable (`/c8s`, `/app/c8s`, `/attestation-api`,
`/docker-entrypoint.sh nginx`) with mounts or env `any`, or with args `any`
outside a sidecar invocation, covers nothing: `c8s allowlist lint` refuses that shape.

`c8s.allowlistSeedJSON` emits `c8s.allowlist/v1`: one workload per derived
image digest outside `c8s.argvPinnedDigests`, with that digest's
`c8s.componentShapes` containers, followed by
`c8s.argvPinnedEntries`, the [router entry](#router-entry) and
`bootstrapAllowlist.workloads`. The volumed entry
also carries the pre-delete teardown hook's script and pause. A
`bootstrapAllowlist.workloads` override named `c8s.digestWorkloadName`
replaces a component entry whole, hook
containers included; an override must declare them too, or the pre-delete hook
is refused and the uninstall fails. The document must satisfy
`pkg/allowlist.ParseJSON`.

## Entry names

`c8s.digestWorkloadName` takes `digest` and `image`, strips the image reference
to its final repository segment, truncates it to 50 characters, substitutes
`image` for an invalid name, and appends the first 12 lowercase digest hex digits.
Keep this naming rule aligned with `pkg/allowlist.DigestEntryName`.

`c8s.shapeWorkloadName` names every entry the chart generates: the component
entries, in the seed and the base alike, and the argv-pinned entries. It cuts
the image segment to 41 characters and appends the first 8 hex digits of the
SHA-256 over the entry's seed-form containers (`c8s.seedContainers`), so the
name stays within 63 characters. A configuration change that alters a shape
without changing a digest names a new entry, which CDS's additive seeding adds
beside the old one; the old entry keeps admitting running pods and rollbacks
until an operator deletes it. `c8s allowlist lint --seed` names such stale
entries. CDS deletes a replaced generated entry itself, the pre-shape
`<image>-<12hex>` form included, when it leaves a component's args or mounts
open (`internal/allowlist` `retiredBySeed`). The node image merges the seed into its measured base, so it carries
the same names.

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
  becomes `$`, and any `$(NAME)` reference fails the render, since the kubelet
  may expand it from env, `envFrom` or a service variable. Escape it as
  `$$(NAME)` and expand it in the binary, as the attestation-api URL does with
  `HOST_IP`; the volumed teardown script is escaped whole.
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
- `env` is `match` over every variable the container launches with
  (`c8s.componentEnv`), so a pod cannot add a loader variable such as
  `LD_PRELOAD` or `BASH_ENV`, nor move `PATH`: containerd's `HOSTNAME`
  (`present`), the image config's `Env` from the component's `imageEnv`
  (`exact`, with containerd's default `PATH` when it sets none), the kubelet's
  `KUBERNETES_*` variables for the API server's Service (`c8s.runtimeEnv`),
  then the container's `env`: a constant `exact`, a `valueFrom` `present`.
  `envFrom`, an optional key reference or a `$(NAME)` reference in a value
  fails the render, since the names or values would depend on objects the
  chart does not render. Every component pod sets `enableServiceLinks: false`,
  so no per-Service variables join the set.

`c8s.injectedShapes` adds the sidecars the webhook injects to the C8s image's
entry: `get-cert`, `probe-file`, `get-secret` and `get-volume`, each pinned to
its invocation with `args: any`, its env matched as above over the variables
the webhook's `getCertEnv` sets (`present`, since they differ per pod; none
for `probe-file`), and one container per combination of the optional
discovery, reload-watch and inventory-socket mounts. The webhook turns service
links off in every pod it injects into. The
destinations match the webhook's fixed ones (`internal/webhook`); the socket
rule's source is `nriImagePolicy.hostPaths.runtimeDir` verbatim, since the NRI
plugin adds that mount without symlink resolution.

`c8s.componentShapes` collects both per digest. Every component digest must
have a rendered container, or the render fails.
[component_mounts_test.go](../../../component_mounts_test.go) checks that the
seed and the base admit every rendered component container exactly as
rendered, with the environment it launches with, and refuse it with one
argument or mount more, one mount fewer, `LD_PRELOAD` set or `PATH` moved, for
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

Names use `c8s.shapeWorkloadName`. `c8s.allowlistSeedJSON` excludes these
digests from its component derivations, adds the pinned entries, then applies
`bootstrapAllowlist.workloads`. An image bump or a changed script produces a
new entry name for additive seeding.

`c8s.argvPinnedDigests` derives its matching digest set from values alone:
calling `argvPinnedEntries` there would recurse through the install script's
boot config. Keep the inclusion conditions of both helpers aligned.

[pinned_seed_test.go](../../../pinned_seed_test.go) checks rendered invocations and mounts,
rejection of different argv, and exclusion from the boot config's local base.
The operator-facing bootstrap behavior is described in
[Allowlist and capabilities](../../../../../docs/allowlist-and-capabilities.md#bootstrap).

## Router entry

The router pod's non-injected containers span two images, so no single-image
entry matches it. `c8s.routerEntry` returns the entry that does, which the
seed names `c8s.routerWorkloadName`. It renders `router.podSpec` and pins each
nginx and c8s-image container through `c8s.podShapes`, exactly as the
component entries pin them: command, args and mount table as rendered, env
matched.

| Container | Declared as |
|---|---|
| nginx | main |
| cds-attest | main |
| allowlist-proxy, when `router.renderAllowlistRoute` | main |
| acme, `c8s-cert`, `c8s-cert-wait` | init |

A declared init container is admitted but not required. A main container with
a hostPath source under `/var/run` has two mount tables (see
`c8s.mountRules`), and a node produces only one. It stays a required main in
the table containerd produces where `/var/run` is `/run`; its other table is
declared as an init container. Where `/var/run` is its own directory the main
is missing and the router pod matches nothing, rather than a partial pod
matching. The router's own `c8s-cert` and `c8s-cert-wait`
are pinned to their exact args, so they are not dropped as injected
containers (`allowlist.AdmitsInjected` takes open args) and the entry declares
them.

`c8s.routerEntryBlocker` returns why the entry cannot be derived, or `""`: the
router is disabled, `router.nginx.image.digest` or `image.digest` is unset,
`bootstrapAllowlist.deriveComponents` is false (it supplies the c8s image's
pin). An argv reference the kubelet would expand fails the render in
`c8s.kubeletExpand`, so the pinned argv is the one the runtime starts.
`c8s.routerWorkloadSeeded` returns `true` when nothing blocks the entry and
`c8s.routerOperatorGate` is empty.

`c8s.routerOperatorGate` returns `router.attest.expectedWorkload` when it is a
non-empty string outside `c8s-router-*`. That names the operator's own router
entry: the chart seeds none, passes the name to cds-attest and the router's
`c8s-cert` as written, and does not check that the entry exists or matches.
The chart does not emulate `MatchWorkload` either: a
`bootstrapAllowlist.workloads` entry that also matches the router pod beside the
seeded one makes the match ambiguous, and CDS issues the router's leaf
unnamed. To supply your own router entry, name it in
`router.attest.expectedWorkload`, which turns the seeded entry off.
`c8s.routerEntryName` returns the seeded entry's name or the operator gate,
which the router's `c8s-cert` receives as `--expected-workload` whenever
workload claims are wired.

`c8s.routerWorkloadName` is `c8s-router-` followed by the first 12 hex digits of
the SHA-256 of the rendered entry, so a changed digest, argv or mount yields a
new name. CDS seeds additively by name, so the new entry lands beside the old
one, as with the digest-named entries. The entry's own name sits inside its
argv: cds-attest's gate, defaulted or an explicit `c8s-router-*` value, and
`c8s-cert`'s `--expected-workload`. The hash therefore renders the pod with
`routerNamePlaceholder` set in the context, under which
`c8s.routerWorkloadName` returns a fixed placeholder; freezing the rendered
default keeps the name.

`router.expectedWorkload` defaults the cds-attest readiness gate to
`c8s.routerWorkloadName` when `router.defaultGate` holds: the gate is unset, the
entry is seeded, `router.hostPort.enabled` is false, and the inventory is
reachable. An explicit string, including `""`, wins;
any other non-null value fails the render. An explicit `c8s-router-*` value
fails the render unless it equals the derived name; when nothing is derivable
the message names `c8s.routerEntryBlocker`'s cause.

[router_entry_test.go](../../../router_entry_test.go) feeds the rendered router
pod, with the argv and mounts a node observes, through
`secrets.WorkloadContainers` and `MatchWorkload`.
