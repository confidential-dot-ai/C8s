{{/* Allowlist helpers. See ../helpers/allowlist/README.md. */}}

{{- define "c8s.valueAtPath" -}}
{{- $cur := .root -}}
{{- range $seg := splitList "." .path -}}
{{- if kindIs "map" $cur -}}{{- $cur = index $cur $seg -}}{{- else -}}{{- $cur = "" -}}{{- end -}}
{{- end -}}
{{- $cur | toJson -}}
{{- end -}}

{{- define "c8s.components" -}}
{{- $root := . -}}
{{- $out := list -}}
{{- range $c := .Values.c8sComponents -}}
{{- $img := include "c8s.valueAtPath" (dict "root" $root.Values "path" $c.valuePath) | fromJson -}}
{{- /* enabledPath points at a JSON boolean; valueAtPath returns it as the
   string "true"/"false". Compare the string rather than `| fromJson`, whose
   Helm variant returns a (truthy) map for a scalar — which silently made this
   gate a no-op, deriving even disabled components that carry a digest. */ -}}
{{- $enabled := true -}}
{{- if $c.enabledPath -}}{{- $enabled = eq (include "c8s.valueAtPath" (dict "root" $root.Values "path" $c.enabledPath)) "true" -}}{{- end -}}
{{- $component := dict "name" $c.valuePath "image" $img "enabled" $enabled "cdsExempt" $c.cdsExempt "argvPinned" (get $c "argvPinned" | default false) "entrypoint" (get $c "entrypoint" | default list) -}}
{{- if hasKey $c "imageEnv" -}}{{- $_ := set $component "imageEnv" (get $c "imageEnv" | default dict) -}}{{- end -}}
{{- $out = append $out $component -}}
{{- end -}}
{{ $out | toJson }}
{{- end -}}

{{/* The chart-deployed system images the seed and the plugin base admit, as
     digest -> {image, entrypoint, containers}. Each is admitted pinned to
     its entrypoint (c8s.componentContainers): the executable is the image's
     own, the arguments and mounts are per-pod, and the environment is
     matched by name. A derived component without an entrypoint or imageEnv
     fails the render: an entry left at any command would admit the image
     under a shell or a mounted binary. */ -}}
{{- define "c8s.imageAllowlist" -}}
{{- $root := . -}}
{{- $digests := dict -}}
{{- $components := include "c8s.components" . | fromJsonArray -}}
{{- if .Values.nriImagePolicy.bootstrapAllowlist.deriveComponents -}}
{{- range $c := $components -}}
{{- $img := get $c "image" -}}
{{- if and (get $c "enabled") (not (get $c "argvPinned")) (get $img "digest") -}}
{{- if not (get $c "entrypoint") -}}
{{- fail (printf "c8sComponents entry %s has no entrypoint: the derived allowlist entry must pin the image's executable" (get $c "name")) -}}
{{- end -}}
{{- $_ := set $digests (get $img "digest") (include "c8s.componentEntry" (dict "root" $root "component" $c "repository" (get $img "repository") "digest" (get $img "digest")) | fromJson) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- $cdsImg := .Values.cds.image -}}
{{- if $cdsImg.digest -}}
{{- $cds := dict -}}
{{- range $c := $components -}}
{{- if eq (get $c "name") "cds.image" -}}{{- $cds = $c -}}{{- end -}}
{{- end -}}
{{- if not (get $cds "entrypoint") -}}
{{- fail "c8sComponents entry cds.image has no entrypoint: the CDS self-entry must pin the image's executable" -}}
{{- end -}}
{{- $_ := set $digests $cdsImg.digest (include "c8s.componentEntry" (dict "root" $root "component" $cds "repository" $cdsImg.repository "digest" $cdsImg.digest) | fromJson) -}}
{{- end -}}
{{- /* router nginx self-entry: a chart-deployed non-c8s system image. It is
       independently versioned and digest-pinned, so it is not in the
       tag-locked c8sComponents derive set (the resolver would `crane digest
       nginx:<c8s-tag>`). Seed it from its pinned digest whenever router is
       enabled — like the CDS self-entry above, independent of deriveComponents
       — so a default install admits the nginx it ships without the operator
       hand-writing an entry for it. */}}
{{- if .Values.router.enabled -}}
{{- $lbImg := .Values.router.nginx.image -}}
{{- if $lbImg.digest -}}
{{- if not .Values.router.nginx.entrypoint -}}
{{- fail "router.nginx.entrypoint is required: the nginx self-entry must pin the image's executable" -}}
{{- end -}}
{{- $nginx := dict "name" "router.nginx" "entrypoint" .Values.router.nginx.entrypoint -}}
{{- if hasKey .Values.router.nginx "imageEnv" -}}{{- $_ := set $nginx "imageEnv" (.Values.router.nginx.imageEnv | default dict) -}}{{- end -}}
{{- $_ := set $digests $lbImg.digest (include "c8s.componentEntry" (dict "root" $root "component" $nginx "repository" $lbImg.repository "digest" $lbImg.digest) | fromJson) -}}
{{- end -}}
{{- end -}}
{{ $digests | toJson }}
{{- end -}}

{{/* One c8s.imageAllowlist value for a component of c8s.components. */ -}}
{{- define "c8s.componentEntry" -}}
{{- $image := printf "%s@%s" .repository .digest -}}
{{- $containers := include "c8s.componentContainers" (dict "root" .root "component" .component "digest" .digest "image" $image) | fromJsonArray -}}
{{ dict "image" $image "entrypoint" (get .component "entrypoint") "containers" $containers | toJson }}
{{- end -}}

{{/* The variables the runtime adds to every component container beside the
     image's and the chart's. containerd's CRI plugin adds HOSTNAME
     (internal/cri/server/container_create.go, containerd v2.1). With service
     links off, the kubelet adds only the variables of the default
     namespace's kubernetes Service (getServiceEnvVarMap in
     pkg/kubelet/kubelet_pods.go and FromServices in pkg/kubelet/envvars,
     Kubernetes v1.34), whose port kube-apiserver fixes at 443
     (APIServerServicePort in cmd/kube-apiserver/app). */ -}}
{{- define "c8s.runtimeEnv" -}}
{{- $present := dict "present" true -}}
{{- $port := dict "exact" "443" -}}
{{- $variables := dict "HOSTNAME" $present "KUBERNETES_SERVICE_HOST" $present "KUBERNETES_SERVICE_PORT" $port "KUBERNETES_SERVICE_PORT_HTTPS" $port -}}
{{- $_ := set $variables "KUBERNETES_PORT" $present -}}
{{- $_ := set $variables "KUBERNETES_PORT_443_TCP" $present -}}
{{- $_ := set $variables "KUBERNETES_PORT_443_TCP_ADDR" $present -}}
{{- $_ := set $variables "KUBERNETES_PORT_443_TCP_PORT" $port -}}
{{- $_ := set $variables "KUBERNETES_PORT_443_TCP_PROTO" (dict "exact" "tcp") -}}
{{ $variables | toJson }}
{{- end -}}

{{/* The env match for one component invocation: the runtime's variables,
     then the image's (pinned exact, PATH among them), then the chart's, each
     overriding the one before as the runtime applies them. containerd sets a
     default PATH when the image sets none (oci.WithDefaultPathEnv). Loader
     variables are never listed, so match rejects them. */ -}}
{{- define "c8s.componentEnv" -}}
{{- $variables := include "c8s.runtimeEnv" . | fromJson -}}
{{- if not (hasKey .imageEnv "PATH") -}}
{{- $_ := set $variables "PATH" (dict "exact" "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin") -}}
{{- end -}}
{{- range $name, $value := .imageEnv -}}{{- $_ := set $variables $name (dict "exact" (toString $value)) -}}{{- end -}}
{{- range $name, $matcher := .variables -}}{{- $_ := set $variables $name $matcher -}}{{- end -}}
{{ dict "policy" "match" "variables" $variables | toJson }}
{{- end -}}

{{/* Every way the chart and the webhook run a component image, by component
     name: the subcommand appended to the entrypoint, and the variables the
     pod spec sets. A fieldRef value, or one that differs per workload, is
     matched present; a constant exact. A component not listed runs its
     entrypoint with no variables. Keep in step with the templates that run
     each image, and the injected sidecars with getCertEnv in
     internal/webhook/pod_mutator.go. */ -}}
{{- define "c8s.componentInvocations" -}}
{{- $present := dict "present" true -}}
{{- $hostIP := dict -}}
{{- if include "c8s.attestationApiHostIPEnv" . -}}{{- $hostIP = dict "HOST_IP" $present -}}{{- end -}}
{{- $injected := dict "C8S_WORKLOAD_ID" $present "C8S_POD_NAME" $present "C8S_POD_UID" $present "HOST_IP" $present -}}
{{- $mesh := dict "NODE_IP" $present -}}
{{- $meshMain := merge (dict) $mesh $hostIP -}}
{{- $c8s := list
  (dict "subcommand" (list "operator") "variables" (dict "POD_NAME" $present))
  (dict "subcommand" (list "attest-proxy") "variables" (dict))
  (dict "subcommand" (list "acme") "variables" (dict))
  (dict "subcommand" (list "cds-attest") "variables" $hostIP)
  (dict "subcommand" (list "allowlist-proxy") "variables" $hostIP)
  (dict "subcommand" (list "get-cert") "variables" $hostIP)
  (dict "subcommand" (list "probe-file") "variables" (dict))
  (dict "subcommand" (list "get-cert") "variables" $injected)
  (dict "subcommand" (list "get-secret") "variables" $injected)
  (dict "subcommand" (list "get-volume") "variables" $injected) -}}
{{- $armtls := list
  (dict "subcommand" (list) "variables" $meshMain)
  (dict "subcommand" (list "iptables-sync") "variables" $mesh)
  (dict "subcommand" (list "iptables-cleanup") "variables" (dict)) -}}
{{ dict "image" $c8s "cds.image" (list (dict "subcommand" (list) "variables" $hostIP)) "armtlsMesh.image" $armtls | toJson }}
{{- end -}}

{{/* The allowlist containers for one component image: one per invocation
     (c8s.componentInvocations), command exact at the entrypoint plus its
     subcommand, args and mounts any, env matched. Admission is the union
     across them. */ -}}
{{- define "c8s.componentContainers" -}}
{{- $component := .component -}}
{{- if not (hasKey $component "imageEnv") -}}
{{- fail (printf "%s has no imageEnv: the derived allowlist entry must match the image's environment" (get $component "name")) -}}
{{- end -}}
{{- $invocations := get (include "c8s.componentInvocations" .root | fromJson) (get $component "name") | default (list (dict "subcommand" (list) "variables" (dict))) -}}
{{- $containers := list -}}
{{- range $i := $invocations -}}
{{- $command := dict "policy" "exact" "argv" (concat (get $component "entrypoint") (get $i "subcommand")) -}}
{{- $env := include "c8s.componentEnv" (dict "imageEnv" (get $component "imageEnv") "variables" (get $i "variables")) | fromJson -}}
{{- $containers = append $containers (dict "digest" $.digest "image" $.image "mounts" (dict "policy" "any") "command" $command "args" (dict "policy" "any") "env" $env) -}}
{{- end -}}
{{ $containers | toJson }}
{{- end -}}

{{/* The volumed image's two other invocations, both in the pre-delete
     teardown hook (volumed-uninstall-hook.yaml): the teardown script and its
     pause. Pinned like the installer's scripts, and seed-only like them: the
     hook runs against a plugin that has pulled the served document, never
     against a cold base. Empty when volumed is off. */ -}}
{{- define "c8s.volumedHookContainers" -}}
{{- $containers := list -}}
{{- if and .Values.volumed.enabled .Values.volumed.image.digest -}}
{{- $img := .Values.volumed.image -}}
{{- $ref := printf "%s@%s" $img.repository $img.digest -}}
{{- $sh := dict "policy" "exact" "argv" (list "/bin/sh" "-c") -}}
{{- $teardown := printf "%s\n" (regexReplaceAll "\n+$" (.Files.Get "files/scripts/volumed-teardown.sh") "") -}}
{{- $imageEnv := dict -}}
{{- range $c := (include "c8s.components" . | fromJsonArray) -}}
{{- if eq (get $c "name") "volumed.image" -}}{{- $imageEnv = get $c "imageEnv" | default dict -}}{{- end -}}
{{- end -}}
{{- $env := include "c8s.componentEnv" (dict "imageEnv" $imageEnv "variables" (dict)) | fromJson -}}
{{- $containers = append $containers (dict "digest" $img.digest "image" $ref "mounts" (dict "policy" "any") "command" $sh "args" (dict "policy" "exact" "argv" (list $teardown)) "env" $env) -}}
{{- $containers = append $containers (dict "digest" $img.digest "image" $ref "command" $sh "args" (dict "policy" "exact" "argv" (list "sleep infinity")) "env" $env) -}}
{{- end -}}
{{ $containers | toJson }}
{{- end -}}

{{/* One allowlist container for a system image from c8s.imageAllowlist:
     command pinned to the entrypoint, args and mounts any. The seed adds an
     explicit env any; the base leaves env absent, which normalizes to any. */ -}}
{{- define "c8s.componentContainer" -}}
{{- $command := dict "policy" "exact" "argv" (get .entry "entrypoint") -}}
{{- $container := dict "digest" .digest "image" (get .entry "image") "mounts" (dict "policy" "any") "command" $command "args" (dict "policy" "any") -}}
{{- if .env -}}{{- $_ := set $container "env" (dict "policy" "any") -}}{{- end -}}
{{ $container | toJson }}
{{- end -}}

{{/* Operator entries that pin at most the command — args, env and mounts any,
     command any or exact — as digest -> {image, entrypoint}, entrypoint empty
     for command any. Both shapes can start a component before CDS is
     reachable, so both feed the base and cover a component for the render
     guard. An entry that pins args, env or mounts is seed-only. */ -}}
{{- define "c8s.openArgsEntries" -}}
{{- $digests := dict -}}
{{- range $name, $entry := (.Values.nriImagePolicy.bootstrapAllowlist.workloads | default dict) -}}
{{- range $c := concat (default list $entry.initContainers) (default list $entry.containers) -}}
{{- $command := dig "command" "policy" "" $c -}}
{{- if and (or (eq $command "any") (eq $command "exact")) (eq (dig "args" "policy" "" $c) "any") (eq (dig "env" "policy" "any" $c) "any") (eq (dig "mounts" "policy" "deny" $c) "any") -}}
{{- $entrypoint := list -}}
{{- if eq $command "exact" -}}
{{- $entrypoint = dig "command" "argv" list $c -}}
{{- if not $entrypoint -}}
{{- fail (printf "nriImagePolicy.bootstrapAllowlist.workloads entry %s pins %s to an exact command with no argv" $name $c.digest) -}}
{{- end -}}
{{- end -}}
{{- /* Two open-args entries for one digest: the base carries the wider pin —
       any over a pin, a prefix over what extends it. Two pins neither of
       which extends the other cannot both reach the base. */ -}}
{{- if hasKey $digests $c.digest -}}
{{- $prior := get (get $digests $c.digest) "entrypoint" -}}
{{- $short := $entrypoint -}}{{- $long := $prior -}}
{{- if gt (len $entrypoint) (len $prior) -}}{{- $short = $prior -}}{{- $long = $entrypoint -}}{{- end -}}
{{- if and $short (ne ($short | toJson) (slice $long 0 (len $short) | toJson)) -}}
{{- fail (printf "nriImagePolicy.bootstrapAllowlist.workloads pin %s to incomparable commands (%s and %s); the base carries one pin per digest, so give the digest one open-args entry" $c.digest ($prior | toJson) ($entrypoint | toJson)) -}}
{{- end -}}
{{- $entrypoint = $short -}}
{{- end -}}
{{- $_ := set $digests $c.digest (dict "image" (default $entry.label $c.image | default "") "entrypoint" $entrypoint) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{ $digests | toJson }}
{{- end -}}

{{/* The plugin boot base, as allowlist workloads keyed by DigestEntryName:
     the chart's system images pinned to their entrypoints, and every digest
     an operator entry admits with open args (c8s.openArgsEntries), under the
     command that entry pins or under any. The boot config excludes
     argv-pinned images, which are admitted by the served seed. */ -}}
{{- define "c8s.baseWorkloads" -}}
{{- $workloads := dict -}}
{{- $pinnedDigests := include "c8s.argvPinnedDigests" . | fromJsonArray -}}
{{- $openArgs := include "c8s.openArgsEntries" . | fromJson -}}
{{- $components := include "c8s.imageAllowlist" . | fromJson -}}
{{- range $digest, $entry := $components -}}
{{- if not (has $digest $pinnedDigests) -}}
{{- $image := get $entry "image" -}}
{{- $name := include "c8s.digestWorkloadName" (dict "digest" $digest "image" $image) -}}
{{- $containers := get $entry "containers" -}}
{{- /* An operator's open-args entry for the same digest: a wider pin (any, or
       a prefix of the entrypoint) replaces the component's; one that pins
       another invocation is admitted beside it, so neither the component nor
       the operator's invocation is refused on a cold node. */ -}}
{{- if hasKey $openArgs $digest -}}
{{- $operator := get $openArgs $digest -}}
{{- $pin := get $operator "entrypoint" -}}
{{- $entrypoint := get $entry "entrypoint" -}}
{{- $wider := le (len $pin) (len $entrypoint) -}}
{{- range $i, $tok := $pin -}}{{- if and $wider (ne $tok (index $entrypoint $i)) -}}{{- $wider = false -}}{{- end -}}{{- end -}}
{{- $container := include "c8s.openArgsContainer" (dict "digest" $digest "entry" $operator) | fromJson -}}
{{- if $wider -}}{{- $containers = list $container -}}{{- else -}}{{- $containers = append $containers $container -}}{{- end -}}
{{- end -}}
{{- $_ := set $workloads $name (dict "label" $image "initContainers" list "containers" $containers) -}}
{{- end -}}
{{- end -}}
{{- range $digest, $entry := $openArgs -}}
{{- if and (not (has $digest $pinnedDigests)) (not (hasKey $components $digest)) -}}
{{- $image := get $entry "image" -}}
{{- $name := include "c8s.digestWorkloadName" (dict "digest" $digest "image" $image) -}}
{{- $container := include "c8s.openArgsContainer" (dict "digest" $digest "entry" $entry) | fromJson -}}
{{- $_ := set $workloads $name (dict "label" $image "initContainers" list "containers" (list $container)) -}}
{{- end -}}
{{- end -}}
{{ $workloads | toJson }}
{{- end -}}

{{/* The base container for an operator open-args entry: pinned to its
     command when it has one, under any command otherwise. */ -}}
{{- define "c8s.openArgsContainer" -}}
{{- if get .entry "entrypoint" -}}
{{- include "c8s.componentContainer" (dict "digest" .digest "entry" .entry "env" false) -}}
{{- else -}}
{{ dict "digest" .digest "image" (get .entry "image") "mounts" (dict "policy" "any") "command" (dict "policy" "any") "args" (dict "policy" "any") | toJson }}
{{- end -}}
{{- end -}}

{{- define "c8s.digestWorkloadName" -}}
{{- $base := .image | splitList "@" | first | splitList "/" | last | splitList ":" | first | trunc 50 -}}
{{- if not (regexMatch "^[A-Za-z0-9][A-Za-z0-9._-]*$" $base) -}}{{- $base = "image" -}}{{- end -}}
{{- printf "%s-%s" $base (.digest | trimPrefix "sha256:" | lower | trunc 12) -}}
{{- end -}}

{{/* See ../helpers/allowlist/README.md#argv-pinned-entries for the seed contract. */}}
{{- define "c8s.argvPinnedEntries" -}}
{{- $entries := dict -}}
{{- if .Values.nriImagePolicy.enabled -}}
{{- $img := .Values.nriImagePolicy.image -}}
{{- $digest := required "nriImagePolicy.image.digest is required (the installer is admitted argv-pinned; a tag cannot be pinned)" $img.digest -}}
{{- $ref := printf "%s@%s" $img.repository $digest -}}
{{- $script := include "nri-image-policy.installScript" (dict "root" . "bootConfig" (include "nri-image-policy.bootConfig" (dict "root" .))) -}}
{{- if .Values.nriImagePolicy.baked -}}
{{- $script = include "nri-image-policy.pinsScript" (dict "root" .) -}}
{{- end -}}
{{- $sh := dict "policy" "exact" "argv" (list "/bin/sh" "-c") -}}
{{- /* Platform setup scripts require host mounts; their executable and script argv stay pinned. */ -}}
{{- $containers := list -}}
{{- $containers = append $containers (dict "digest" $digest "image" $ref "mounts" (dict "policy" "any") "command" $sh "args" (dict "policy" "exact" "argv" (list (printf "%s\n" (regexReplaceAll "\n+$" $script ""))))) -}}
{{- if .Values.nriImagePolicy.uninstall.enabled -}}
{{- $containers = append $containers (dict "digest" $digest "image" $ref "mounts" (dict "policy" "any") "command" $sh "args" (dict "policy" "exact" "argv" (list (printf "%s\n" (regexReplaceAll "\n+$" (.Files.Get "files/scripts/uninstall.sh") ""))))) -}}
{{- end -}}
{{- $containers = append $containers (dict "digest" $digest "image" $ref "command" $sh "args" (dict "policy" "exact" "argv" (list "sleep infinity"))) -}}
{{- $containers = append $containers (dict "digest" $digest "image" $ref "command" $sh "args" (dict "policy" "exact" "argv" (list (include "nri-image-policy.pluginReadyScript" .)))) -}}
{{- $containers = append $containers (dict "digest" $digest "image" $ref "mounts" (dict "policy" "any") "command" $sh "args" (dict "policy" "exact" "argv" (list (printf "%s\n" (regexReplaceAll "\n+$" (.Files.Get "files/scripts/host-sweep.sh") ""))))) -}}
{{- $containers = append $containers (dict "digest" $digest "image" $ref "command" (dict "policy" "exact" "argv" (list "/bin/sleep")) "args" (dict "policy" "exact" "argv" (list "2147483647"))) -}}
{{- $name := include "c8s.digestWorkloadName" (dict "digest" $digest "image" $ref) -}}
{{- $_ := set $entries $name (dict "label" $ref "initContainers" list "containers" $containers) -}}
{{- $prepScript := .Files.Get "files/scripts/containerd-prep.sh" -}}
{{- $prepDigests := dict -}}
{{- if and (eq .Values.nriImagePolicy.distro "rke2") (not .Values.nriImagePolicy.baked) -}}
{{- with .Values.nriImagePolicy.containerdPrep.image -}}
{{- if .digest -}}{{- $_ := set $prepDigests .digest (printf "%s@%s" .repository .digest) -}}{{- end -}}
{{- end -}}
{{- end -}}
{{- range $digest, $ref := $prepDigests -}}
{{- $container := dict "digest" $digest "image" $ref "mounts" (dict "policy" "any") "command" $sh "args" (dict "policy" "exact" "argv" (list (printf "%s\n" (regexReplaceAll "\n+$" $prepScript "")))) -}}
{{- $name := include "c8s.digestWorkloadName" (dict "digest" $digest "image" $ref) -}}
{{- $_ := set $entries $name (dict "label" $ref "initContainers" list "containers" (list $container)) -}}
{{- end -}}
{{- end -}}
{{- if eq .Values.attestationApi.cvmMode "bare-metal" -}}
{{- $img := .Values.rke2.localPathHelper.image -}}
{{- if $img.digest -}}
{{- $ref := printf "%s@%s" $img.repository $img.digest -}}
{{- $containers := list -}}
{{- range $path := list "/script/setup" "/script/teardown" -}}
{{- $containers = append $containers (dict "digest" $img.digest "image" $ref "mounts" (dict "policy" "any") "command" (dict "policy" "exact" "argv" (list "/bin/sh" $path)) "args" (dict "policy" "any")) -}}
{{- end -}}
{{- $name := include "c8s.digestWorkloadName" (dict "digest" $img.digest "image" $ref) -}}
{{- $_ := set $entries $name (dict "label" $ref "initContainers" list "containers" $containers) -}}
{{- end -}}
{{- end -}}
{{ $entries | toJson }}
{{- end -}}

{{/* Values-only to avoid boot-config recursion; see ../helpers/allowlist/README.md#argv-pinned-entries. */}}
{{- define "c8s.argvPinnedDigests" -}}
{{- $digests := list -}}
{{- if and .Values.nriImagePolicy.enabled .Values.nriImagePolicy.image.digest -}}
{{- $digests = append $digests .Values.nriImagePolicy.image.digest -}}
{{- if and (eq .Values.nriImagePolicy.distro "rke2") (not .Values.nriImagePolicy.baked) .Values.nriImagePolicy.containerdPrep.image.digest -}}
{{- $digests = append $digests .Values.nriImagePolicy.containerdPrep.image.digest -}}
{{- end -}}
{{- end -}}
{{- if and (eq .Values.attestationApi.cvmMode "bare-metal") .Values.rke2.localPathHelper.image.digest -}}
{{- $digests = append $digests .Values.rke2.localPathHelper.image.digest -}}
{{- end -}}
{{ $digests | toJson }}
{{- end -}}

{{- define "c8s.allowlistSeedJSON" -}}
{{- $root := . -}}
{{- $workloads := dict -}}
{{- $pinnedDigests := include "c8s.argvPinnedDigests" . | fromJsonArray -}}
{{- $hookContainers := include "c8s.volumedHookContainers" . | fromJsonArray -}}
{{- range $digest, $entry := (include "c8s.imageAllowlist" . | fromJson) -}}
{{- if not (has $digest $pinnedDigests) -}}
{{- $image := get $entry "image" -}}
{{- $name := include "c8s.digestWorkloadName" (dict "digest" $digest "image" $image) -}}
{{- $containers := get $entry "containers" -}}
{{- if eq $digest (default "" $root.Values.volumed.image.digest) -}}
{{- $containers = concat $containers $hookContainers -}}
{{- end -}}
{{- $_ := set $workloads $name (dict "label" $image "initContainers" list "containers" $containers) -}}
{{- end -}}
{{- end -}}
{{- range $name, $entry := (include "c8s.argvPinnedEntries" . | fromJson) -}}
{{- $_ := set $workloads $name $entry -}}
{{- end -}}
{{- range $name, $entry := (.Values.nriImagePolicy.bootstrapAllowlist.workloads | default dict) -}}
{{- $_ := set $workloads $name $entry -}}
{{- end -}}
{{ dict "schema" "c8s.allowlist/v1" "workloads" $workloads | toJson }}
{{- end -}}
