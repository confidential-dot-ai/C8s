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
{{- $out = append $out (dict "name" $c.valuePath "image" $img "enabled" $enabled "cdsExempt" $c.cdsExempt "argvPinned" (get $c "argvPinned" | default false) "entrypoint" (get $c "entrypoint" | default list)) -}}
{{- end -}}
{{ $out | toJson }}
{{- end -}}

{{/* The chart-deployed system images the seed and the plugin base admit, as
     digest -> {image, entrypoint}. Each is admitted pinned to its entrypoint
     (c8s.componentContainer): the executable is the image's own, while the
     arguments, environment and mounts are per-pod. A derived component
     without an entrypoint fails the render: an entry left at any command
     would admit the image under a shell or a mounted binary. */ -}}
{{- define "c8s.imageAllowlist" -}}
{{- $digests := dict -}}
{{- $components := include "c8s.components" . | fromJsonArray -}}
{{- if .Values.nriImagePolicy.bootstrapAllowlist.deriveComponents -}}
{{- range $c := $components -}}
{{- $img := get $c "image" -}}
{{- if and (get $c "enabled") (not (get $c "argvPinned")) (get $img "digest") -}}
{{- if not (get $c "entrypoint") -}}
{{- fail (printf "c8sComponents entry %s has no entrypoint: the derived allowlist entry must pin the image's executable" (get $c "name")) -}}
{{- end -}}
{{- $_ := set $digests (get $img "digest") (dict "image" (printf "%s@%s" (get $img "repository") (get $img "digest")) "entrypoint" (get $c "entrypoint")) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- $cdsImg := .Values.cds.image -}}
{{- if $cdsImg.digest -}}
{{- $cdsEntrypoint := list -}}
{{- range $c := $components -}}
{{- if eq (get $c "name") "cds.image" -}}{{- $cdsEntrypoint = get $c "entrypoint" -}}{{- end -}}
{{- end -}}
{{- if not $cdsEntrypoint -}}
{{- fail "c8sComponents entry cds.image has no entrypoint: the CDS self-entry must pin the image's executable" -}}
{{- end -}}
{{- $_ := set $digests $cdsImg.digest (dict "image" (printf "%s@%s" $cdsImg.repository $cdsImg.digest) "entrypoint" $cdsEntrypoint) -}}
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
{{- $_ := set $digests $lbImg.digest (dict "image" (printf "%s@%s" $lbImg.repository $lbImg.digest) "entrypoint" .Values.router.nginx.entrypoint) -}}
{{- end -}}
{{- end -}}
{{ $digests | toJson }}
{{- end -}}

{{/* The pod specs of the enabled component workloads, as a JSON list of
     {name, spec}: the same named templates the workloads render, so the
     shapes derived from them cannot drift from what runs. */ -}}
{{- define "c8s.componentPods" -}}
{{- $templates := list (list "operator" "c8s.operatorPodSpec") (list "cds" "c8s.cdsPodSpec") -}}
{{- if .Values.attestationApi.enabled -}}{{- $templates = append $templates (list "attestation-api" "c8s.attestationApiPodSpec") -}}{{- end -}}
{{- if .Values.armtlsMesh.enabled -}}{{- $templates = append $templates (list "armtls-mesh" "armtls-mesh.podSpec") -}}{{- end -}}
{{- if .Values.volumed.enabled -}}
{{- $templates = append $templates (list "volumed" "c8s.volumedPodSpec") -}}
{{- $templates = append $templates (list "volumed-teardown" "c8s.volumedTeardownPodSpec") -}}
{{- end -}}
{{- if .Values.router.enabled -}}{{- $templates = append $templates (list "router" "router.podSpec") -}}{{- end -}}
{{- $pods := list -}}
{{- range $t := $templates -}}
{{- $spec := include (index $t 1) $ | fromYaml -}}
{{- if hasKey $spec "Error" -}}
{{- fail (printf "%s pod spec does not parse: %s" (index $t 0) (get $spec "Error")) -}}
{{- end -}}
{{- $pods = append $pods (dict "name" (index $t 0) "spec" $spec) -}}
{{- end -}}
{{ $pods | toJson }}
{{- end -}}

{{/* The allowlist containers for one pod's containers whose image is a
     component digest: command, args and mounts exactly as the pod spec gives
     them. Takes name, spec, pins (digest -> entrypoint) and refs (digest ->
     image reference). See ../helpers/allowlist/README.md#component-shapes. */ -}}
{{- define "c8s.podShapes" -}}
{{- $pod := .name -}}
{{- $volumes := dict -}}
{{- range $v := (default list .spec.volumes) -}}{{- $_ := set $volumes $v.name $v -}}{{- end -}}
{{- $out := list -}}
{{- range $c := concat (default list .spec.initContainers) (default list .spec.containers) -}}
{{- $digest := "" -}}
{{- if contains "@" $c.image -}}{{- $digest = last (splitList "@" $c.image) -}}{{- end -}}
{{- if hasKey $.pins $digest -}}
{{- $where := printf "%s container %s" $pod $c.name -}}
{{- $command := include "c8s.kubeletExpand" (dict "argv" (default list $c.command) "env" (default list $c.env) "where" $where) | fromJsonArray -}}
{{- $args := include "c8s.kubeletExpand" (dict "argv" (default list $c.args) "env" (default list $c.env) "where" $where) | fromJsonArray -}}
{{- if and (not $command) (not $args) -}}
{{- fail (printf "%s runs its image's CMD: spell out its args so the allowlist can pin them" $where) -}}
{{- end -}}
{{- $pin := get $.pins $digest -}}
{{- $argv := concat (ternary $command $pin (gt (len $command) 0)) $args -}}
{{- $commandPolicy := dict -}}
{{- $rest := list -}}
{{- if and (ge (len $argv) (len $pin)) (eq (slice $argv 0 (len $pin) | toJson) ($pin | toJson)) -}}
{{- $commandPolicy = dict "policy" "exact" "argv" $pin -}}
{{- $rest = slice $argv (len $pin) -}}
{{- else -}}
{{- $commandPolicy = dict "policy" "exact" "argv" $command -}}
{{- $rest = $args -}}
{{- end -}}
{{- $argsPolicy := dict "policy" "deny" -}}
{{- if $rest -}}{{- $argsPolicy = dict "policy" "exact" "argv" $rest -}}{{- end -}}
{{- $mounts := include "c8s.mountRules" (dict "mounts" (default list $c.volumeMounts) "volumes" $volumes "where" $where) | fromJsonArray -}}
{{- range $rules := $mounts -}}
{{- $mountPolicy := dict "policy" "deny" -}}
{{- if $rules -}}{{- $mountPolicy = dict "policy" "exact" "rules" $rules -}}{{- end -}}
{{- $shape := dict "digest" $digest "image" (get $.refs $digest) "command" $commandPolicy "args" $argsPolicy "mounts" $mountPolicy -}}
{{- if not (has $shape $out) -}}{{- $out = append $out $shape -}}{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{ $out | toJson }}
{{- end -}}

{{/* The argv the kubelet hands the runtime: $$ becomes $, and $(NAME) for a
     variable the container defines becomes its value. A per-node value
     cannot be pinned, so a component's argv must not reference one; escape
     it as $$(NAME) and expand it in the binary instead. */ -}}
{{- define "c8s.kubeletExpand" -}}
{{- $out := list -}}
{{- range $token := .argv -}}
{{- $token = replace "$$" "\x00" (toString $token) -}}
{{- range $e := $.env -}}
{{- if contains (printf "$(%s)" $e.name) $token -}}
{{- fail (printf "%s references $(%s) in its argv; the allowlist pins the argv exactly, so pass the value another way" $.where $e.name) -}}
{{- end -}}
{{- end -}}
{{- $out = append $out (replace "\x00" "$" $token) -}}
{{- end -}}
{{ $out | toJson }}
{{- end -}}

{{/* The exact mount rules for one container, as a JSON list of rule lists:
     one per host layout. containerd resolves symlinks in a hostPath source,
     and /var/run is a symlink to /run on most nodes, so a container with a
     source under /var/run gets a second rule list with the resolved path;
     the entry admits whichever the node produces. */ -}}
{{- define "c8s.mountRules" -}}
{{- $layouts := list (list) (list) -}}
{{- $resolves := false -}}
{{- $seen := dict -}}
{{- range $m := .mounts -}}
{{- $v := get $.volumes $m.name -}}
{{- $where := printf "%s mount %s" $.where $m.name -}}
{{- if not $v -}}{{- fail (printf "%s names no volume" $where) -}}{{- end -}}
{{- if $m.subPath -}}{{- fail (printf "%s uses a subPath, which the node classifies as data: mount the whole volume" $where) -}}{{- end -}}
{{- $dest := toString $m.mountPath -}}
{{- if or (not (isAbs $dest)) (ne (clean $dest) $dest) -}}{{- fail (printf "%s destination %q is not a clean absolute path" $where $dest) -}}{{- end -}}
{{- if hasKey $seen $dest -}}{{- fail (printf "%s destination %q is mounted twice" $where $dest) -}}{{- end -}}
{{- $_ := set $seen $dest true -}}
{{- $rule := dict "destination" $dest -}}
{{- $resolved := dict "destination" $dest -}}
{{- if hasKey $v "hostPath" -}}
{{- $source := toString $v.hostPath.path -}}
{{- if or (not (isAbs $source)) (ne (clean $source) $source) -}}{{- fail (printf "%s host path %q is not a clean absolute path" $where $source) -}}{{- end -}}
{{- $rule = dict "destination" $dest "kind" "host" "source" $source -}}
{{- $target := $source -}}
{{- if or (eq $source "/var/run") (hasPrefix "/var/run/" $source) -}}
{{- $target = printf "/run%s" (trimPrefix "/var/run" $source) -}}
{{- $resolves = true -}}
{{- end -}}
{{- $resolved = dict "destination" $dest "kind" "host" "source" $target -}}
{{- if $m.readOnly -}}
{{- $_ := set $rule "readOnly" true -}}
{{- $_ := set $resolved "readOnly" true -}}
{{- end -}}
{{- else if hasKey $v "emptyDir" -}}
{{- $rule = dict "destination" $dest "kind" "emptyDir" -}}
{{- $resolved = $rule -}}
{{- else if or (hasKey $v "configMap") (hasKey $v "secret") (hasKey $v "projected") (hasKey $v "downwardAPI") (hasKey $v "persistentVolumeClaim") -}}
{{- if not (hasPrefix "/mnt/c8s-data/" $dest) -}}
{{- fail (printf "%s mounts a ConfigMap, Secret or PVC at %q: data volumes must sit under /mnt/c8s-data/" $where $dest) -}}
{{- end -}}
{{- $rule = dict "destination" $dest "kind" "data" -}}
{{- $resolved = $rule -}}
{{- else -}}
{{- fail (printf "%s has a volume source the allowlist cannot pin" $where) -}}
{{- end -}}
{{- $layouts = list (append (index $layouts 0) $rule) (append (index $layouts 1) $resolved) -}}
{{- end -}}
{{- if $resolves -}}{{ $layouts | toJson }}{{- else -}}{{ list (index $layouts 0) | toJson }}{{- end -}}
{{- end -}}

{{/* The shapes of the sidecars the webhook injects with the C8s image
     (internal/webhook): each pinned to its invocation with args open, since
     the SAN and file paths are per pod, and to a fixed mount table. The
     discovery, reload-watch and inventory socket mounts are optional, so each
     combination is its own shape. The destinations match the webhook's
     defaults, which pods can no longer move. */ -}}
{{- define "c8s.injectedShapes" -}}
{{- $certs := dict "destination" "/etc/c8s/certs" "kind" "emptyDir" -}}
{{- $discovery := dict "destination" "/run/c8s/discovery" "kind" "emptyDir" -}}
{{- $reload := dict "destination" "/mnt/c8s-data/c8s-reload-watch" "kind" "data" -}}
{{- $secrets := dict "destination" "/run/c8s/secrets" "kind" "emptyDir" -}}
{{- /* An NRI mount, so containerd does not resolve the source: it is the
       plugin's configured socket directory verbatim. */ -}}
{{- $socket := dict "destination" "/run/c8s/workload-claims" "kind" "host" "source" (toString .root.Values.nriImagePolicy.hostPaths.runtimeDir) "readOnly" true -}}
{{- $sidecars := list
      (dict "mode" "get-cert" "fixed" (list $certs) "optional" (list $discovery $reload $socket))
      (dict "mode" "probe-file" "fixed" (list $certs) "optional" (list $discovery))
      (dict "mode" "get-secret" "fixed" (list $certs $secrets) "optional" (list $discovery $socket))
      (dict "mode" "get-volume" "fixed" (list $certs) "optional" (list $discovery $socket)) -}}
{{- $out := list -}}
{{- range $s := $sidecars -}}
{{- $tables := list (get $s "fixed") -}}
{{- range $m := get $s "optional" -}}
{{- $grown := list -}}
{{- range $t := $tables -}}{{- $grown = append (append $grown $t) (append $t $m) -}}{{- end -}}
{{- $tables = $grown -}}
{{- end -}}
{{- range $t := $tables -}}
{{- $out = append $out (dict "digest" $.digest "image" $.image "command" (dict "policy" "exact" "argv" (list "/c8s" (get $s "mode"))) "args" (dict "policy" "any") "mounts" (dict "policy" "exact" "rules" $t)) -}}
{{- end -}}
{{- end -}}
{{ $out | toJson }}
{{- end -}}

{{/* Every component shape the chart runs, as digest -> {image, containers}:
     the containers of the component pods (c8s.podShapes) and, for the C8s
     image, the sidecars the webhook injects (c8s.injectedShapes). Only the
     digests c8s.imageAllowlist derives are included. */ -}}
{{- define "c8s.componentShapes" -}}
{{- $components := include "c8s.imageAllowlist" . | fromJson -}}
{{- $pins := dict -}}
{{- $refs := dict -}}
{{- range $digest, $entry := $components -}}
{{- $_ := set $pins $digest (get $entry "entrypoint") -}}
{{- $_ := set $refs $digest (get $entry "image") -}}
{{- end -}}
{{- $shapes := dict -}}
{{- range $pod := (include "c8s.componentPods" . | fromJsonArray) -}}
{{- range $c := (include "c8s.podShapes" (dict "name" (get $pod "name") "spec" (get $pod "spec") "pins" $pins "refs" $refs) | fromJsonArray) -}}
{{- $list := get $shapes (get $c "digest") | default list -}}
{{- if not (has $c $list) -}}{{- $_ := set $shapes (get $c "digest") (append $list $c) -}}{{- end -}}
{{- end -}}
{{- end -}}
{{- $operator := default "" .Values.image.digest -}}
{{- if hasKey $components $operator -}}
{{- $injected := include "c8s.injectedShapes" (dict "root" . "digest" $operator "image" (get $refs $operator)) | fromJsonArray -}}
{{- $_ := set $shapes $operator (concat (get $shapes $operator | default list) $injected) -}}
{{- end -}}
{{- $out := dict -}}
{{- range $digest, $entry := $components -}}
{{- if not (hasKey $shapes $digest) -}}
{{- fail (printf "%s is a component digest no rendered container runs" (get $entry "image")) -}}
{{- end -}}
{{- $_ := set $out $digest (dict "image" (get $entry "image") "containers" (get $shapes $digest)) -}}
{{- end -}}
{{ $out | toJson }}
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

{{/* Operator entries for a component digest that pin more than the command:
     args, env or mounts. Such an entry starts the component as surely as an
     open-args one, so it reaches the base verbatim and covers the component
     for the render guard. As digest -> list of containers. */ -}}
{{- define "c8s.pinnedComponentEntries" -}}
{{- $componentDigests := list -}}
{{- range $c := (include "c8s.components" . | fromJsonArray) -}}
{{- with get (get $c "image") "digest" -}}{{- $componentDigests = append $componentDigests . -}}{{- end -}}
{{- end -}}
{{- with .Values.router.nginx.image.digest -}}{{- $componentDigests = append $componentDigests . -}}{{- end -}}
{{- $digests := dict -}}
{{- range $name, $entry := (.Values.nriImagePolicy.bootstrapAllowlist.workloads | default dict) -}}
{{- range $c := concat (default list $entry.initContainers) (default list $entry.containers) -}}
{{- $command := dig "command" "policy" "" $c -}}
{{- $open := and (eq (dig "args" "policy" "" $c) "any") (eq (dig "env" "policy" "any" $c) "any") (eq (dig "mounts" "policy" "deny" $c) "any") -}}
{{- if and (or (eq $command "any") (eq $command "exact")) (not $open) (has $c.digest $componentDigests) -}}
{{- $_ := set $digests $c.digest (append (get $digests $c.digest | default list) $c) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{ $digests | toJson }}
{{- end -}}

{{/* The plugin boot base, as allowlist workloads keyed by DigestEntryName:
     the chart's component shapes (c8s.componentShapes), every digest an
     operator entry admits with open args (c8s.openArgsEntries) under the
     command that entry pins or under any, and the operator's own entries for
     a component digest (c8s.pinnedComponentEntries). The boot config
     excludes argv-pinned images, which are admitted by the served seed. */ -}}
{{- define "c8s.baseWorkloads" -}}
{{- $workloads := dict -}}
{{- $pinnedDigests := include "c8s.argvPinnedDigests" . | fromJsonArray -}}
{{- $openArgs := include "c8s.openArgsEntries" . | fromJson -}}
{{- $operatorPins := include "c8s.pinnedComponentEntries" . | fromJson -}}
{{- $components := include "c8s.componentShapes" . | fromJson -}}
{{- $images := dict -}}
{{- $containers := dict -}}
{{- range $digest, $entry := $components -}}
{{- $_ := set $images $digest (get $entry "image") -}}
{{- $_ := set $containers $digest (get $entry "containers") -}}
{{- end -}}
{{- range $digest, $entry := $openArgs -}}
{{- if not (hasKey $images $digest) -}}{{- $_ := set $images $digest (get $entry "image") -}}{{- end -}}
{{- $container := include "c8s.openArgsContainer" (dict "digest" $digest "entry" $entry) | fromJson -}}
{{- $_ := set $containers $digest (append (get $containers $digest | default list) $container) -}}
{{- end -}}
{{- range $digest, $list := $operatorPins -}}
{{- if not (hasKey $images $digest) -}}{{- $_ := set $images $digest (default "" (get (first $list) "image")) -}}{{- end -}}
{{- $_ := set $containers $digest (concat (get $containers $digest | default list) $list) -}}
{{- end -}}
{{- range $digest, $list := $containers -}}
{{- if not (has $digest $pinnedDigests) -}}
{{- $image := get $images $digest -}}
{{- $name := include "c8s.digestWorkloadName" (dict "digest" $digest "image" $image) -}}
{{- $_ := set $workloads $name (dict "label" $image "initContainers" list "containers" $list) -}}
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
{{- $workloads := dict -}}
{{- $pinnedDigests := include "c8s.argvPinnedDigests" . | fromJsonArray -}}
{{- range $digest, $entry := (include "c8s.componentShapes" . | fromJson) -}}
{{- if not (has $digest $pinnedDigests) -}}
{{- $image := get $entry "image" -}}
{{- $name := include "c8s.digestWorkloadName" (dict "digest" $digest "image" $image) -}}
{{- $containers := list -}}
{{- range $c := get $entry "containers" -}}
{{- $containers = append $containers (merge (dict "env" (dict "policy" "any")) $c) -}}
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
