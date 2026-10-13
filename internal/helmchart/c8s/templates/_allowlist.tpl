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
{{- $out = append $out (dict "name" $c.valuePath "image" $img "enabled" $enabled "cdsExempt" $c.cdsExempt "argvPinned" (get $c "argvPinned" | default false)) -}}
{{- end -}}
{{ $out | toJson }}
{{- end -}}

{{- define "c8s.imageAllowlist" -}}
{{- $digests := dict -}}
{{- if .Values.nriImagePolicy.bootstrapAllowlist.deriveComponents -}}
{{- range $c := (include "c8s.components" . | fromJsonArray) -}}
{{- $img := get $c "image" -}}
{{- if and (get $c "enabled") (not (get $c "argvPinned")) (get $img "digest") -}}
{{- $_ := set $digests (get $img "digest") (printf "%s@%s" (get $img "repository") (get $img "digest")) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- $cdsImg := .Values.cds.image -}}
{{- if $cdsImg.digest -}}
{{- $_ := set $digests $cdsImg.digest (printf "%s@%s" $cdsImg.repository $cdsImg.digest) -}}
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
{{- $_ := set $digests $lbImg.digest (printf "%s@%s" $lbImg.repository $lbImg.digest) -}}
{{- end -}}
{{- end -}}
{{ $digests | toJson }}
{{- end -}}

{{- define "c8s.anyArgvDigests" -}}
{{- $digests := dict -}}
{{- range $name, $entry := (.Values.nriImagePolicy.bootstrapAllowlist.workloads | default dict) -}}
{{- range $c := concat (default list $entry.initContainers) (default list $entry.containers) -}}
{{- if and (eq (dig "command" "policy" "" $c) "any") (eq (dig "args" "policy" "" $c) "any") (eq (dig "env" "policy" "any" $c) "any") (eq (dig "mounts" "policy" "deny" $c) "any") -}}
{{- $_ := set $digests $c.digest (default $entry.label $c.image | default "") -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{ $digests | toJson }}
{{- end -}}

{{/* The plugin boot base, as allowlist workloads: every digest the base
     admits under any command line, keyed by its DigestEntryName. The boot
     config excludes argv-pinned images, which are admitted by the served seed. */ -}}
{{- define "c8s.baseWorkloads" -}}
{{- $workloads := dict -}}
{{- $pinnedDigests := include "c8s.argvPinnedDigests" . | fromJsonArray -}}
{{- range $digest, $image := (merge (include "c8s.anyArgvDigests" . | fromJson) (include "c8s.imageAllowlist" . | fromJson)) -}}
{{- if not (has $digest $pinnedDigests) -}}
{{- $name := include "c8s.digestWorkloadName" (dict "digest" $digest "image" $image) -}}
{{- $container := dict "digest" $digest "image" $image "mounts" (dict "policy" "any") "command" (dict "policy" "any") "args" (dict "policy" "any") -}}
{{- $_ := set $workloads $name (dict "label" $image "initContainers" list "containers" (list $container)) -}}
{{- end -}}
{{- end -}}
{{ $workloads | toJson }}
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

{{/* The router pod's workload entry. See ../helpers/allowlist/README.md#router-entry. */}}
{{- define "c8s.routerArgv" -}}
{{- $root := .root -}}
{{- $argv := dict -}}
{{- if $root.Values.router.attest.enabled -}}
{{- $_ := set $argv "cds-attest" (include "router.cdsAttestArgs" . | fromJsonArray) -}}
{{- end -}}
{{- if eq (include "router.renderAllowlistRoute" $root) "true" -}}
{{- $_ := set $argv "allowlist-proxy" (include "router.allowlistProxyArgs" $root | fromJsonArray) -}}
{{- end -}}
{{- if eq (include "router.acmeSidecar" $root) "true" -}}
{{- $_ := set $argv "acme" (include "router.acmeArgs" $root | fromJsonArray) -}}
{{- end -}}
{{ $argv | toJson }}
{{- end -}}

{{- /* Values-only apart from argv, so router.expectedWorkload can call it.
       deriveComponents seeds the c8s image's any-argv entry, without which
       get-cert is not dropped as injected and the router cannot match. */ -}}
{{- /* Names of bootstrapAllowlist.workloads entries listing both router
       images, as a JSON list. */ -}}
{{- define "c8s.operatorRouterEntries" -}}
{{- $nginx := .Values.router.nginx.image.digest -}}
{{- $c8s := .Values.image.digest -}}
{{- $names := list -}}
{{- range $name, $entry := (.Values.nriImagePolicy.bootstrapAllowlist.workloads | default dict) -}}
{{- $digests := list -}}
{{- range $c := concat (default list $entry.initContainers) (default list $entry.containers) -}}
{{- $digests = append $digests $c.digest -}}
{{- end -}}
{{- if and $nginx $c8s (has $nginx $digests) (has $c8s $digests) -}}
{{- $names = append $names $name -}}
{{- end -}}
{{- end -}}
{{ $names | toJson }}
{{- end -}}

{{- define "c8s.routerWorkloadSeeded" -}}
{{- $explicit := .Values.router.attest.expectedWorkload -}}
{{- /* A gate naming an operator entry for the router replaces the seeded
       one, which would otherwise make the router's match ambiguous. */ -}}
{{- $operatorEntry := and (kindIs "string" $explicit) (has $explicit (include "c8s.operatorRouterEntries" . | fromJsonArray)) -}}
{{- if and .Values.router.enabled (not $operatorEntry) .Values.nriImagePolicy.bootstrapAllowlist.deriveComponents .Values.router.nginx.image.digest .Values.image.digest (or .Values.router.attest.enabled (eq (include "router.renderAllowlistRoute" .) "true")) -}}
{{- $argv := include "c8s.routerArgv" (dict "root" . "expectedWorkload" (ternary $explicit "" (kindIs "string" $explicit))) -}}
{{- /* kubelet expands $(VAR) and $$ in args, so such argv is not known here. */ -}}
{{- if not (contains "$" $argv) -}}true{{- end -}}
{{- end -}}
{{- end -}}

{{- /* Takes (dict "root" $ "expectedWorkload" <name>). */ -}}
{{- define "c8s.routerEntry" -}}
{{- $root := .root -}}
{{- $any := dict "policy" "any" -}}
{{- $nginx := $root.Values.router.nginx.image -}}
{{- $containers := list (dict "digest" $nginx.digest "image" (printf "%s@%s" $nginx.repository $nginx.digest) "command" $any "args" $any "mounts" $any "env" $any) -}}
{{- $inits := list -}}
{{- $ref := printf "%s@%s" $root.Values.image.repository $root.Values.image.digest -}}
{{- /* The c8s image's ENTRYPOINT, like secrets.InjectedBinary. */ -}}
{{- $entrypoint := dict "policy" "exact" "argv" (list "/c8s") -}}
{{- range $name, $args := (include "c8s.routerArgv" . | fromJson) -}}
{{- $c := dict "digest" $root.Values.image.digest "image" $ref "command" $entrypoint "args" (dict "policy" "exact" "argv" $args) "mounts" $any "env" $any -}}
{{- /* acme is a native sidecar: declared init, so present but not required. */ -}}
{{- if eq $name "acme" -}}
{{- $inits = append $inits $c -}}
{{- else -}}
{{- $containers = append $containers $c -}}
{{- end -}}
{{- end -}}
{{ dict "initContainers" $inits "containers" $containers | toJson }}
{{- end -}}

{{- /* c8s-router-<12 hex of sha256 over the entry>, so a changed digest or
       argv seeds a new entry. A gate naming this entry, defaulted or an
       explicit c8s-router-* value, sits inside its own cds-attest argv, so
       its --expected-workload is hashed as a fixed placeholder. */ -}}
{{- define "c8s.routerWorkloadName" -}}
{{- $explicit := .Values.router.attest.expectedWorkload -}}
{{- $namesEntry := and (kindIs "string" $explicit) (hasPrefix "c8s-router-" $explicit) -}}
{{- $gate := "" -}}
{{- if and (kindIs "string" $explicit) (not $namesEntry) -}}
{{- $gate = $explicit -}}
{{- else if or $namesEntry (eq (include "router.defaultGate" .) "true") -}}
{{- $gate = "<default>" -}}
{{- end -}}
{{- $name := printf "c8s-router-%s" (include "c8s.routerEntry" (dict "root" . "expectedWorkload" $gate) | sha256sum | trunc 12) -}}
{{- if and $namesEntry (ne $explicit $name) -}}
{{- fail (printf "router.attest.expectedWorkload=%s does not name the seeded router entry, which these values name %s: set it to %s, or leave it unset to follow the entry" $explicit $name $name) -}}
{{- end -}}
{{- $name -}}
{{- end -}}

{{- /* Fails the render when the router pod would match several entries, or
       a gate names an operator entry that lacks a router image; either way
       its leaf is never stamped with the gated name. */ -}}
{{- define "c8s.routerWorkload" -}}
{{- if .Values.router.enabled -}}
{{- $explicit := .Values.router.attest.expectedWorkload -}}
{{- $operator := include "c8s.operatorRouterEntries" . | fromJsonArray -}}
{{- $seeded := eq (include "c8s.routerWorkloadSeeded" .) "true" -}}
{{- $matching := $operator -}}
{{- if $seeded -}}
{{- $matching = append $operator (include "c8s.routerWorkloadName" .) | uniq -}}
{{- end -}}
{{- if gt (len $matching) 1 -}}
{{- fail (printf "nriImagePolicy.bootstrapAllowlist.workloads lists router.nginx.image.digest and image.digest together, so the router pod would match each of %s and never be stamped: keep one router entry, or set router.attest.expectedWorkload to an operator entry to replace the seeded one" (join ", " (sortAlpha $matching))) -}}
{{- end -}}
{{- if and (kindIs "string" $explicit) (not (hasPrefix "c8s-router-" $explicit)) (hasKey (.Values.nriImagePolicy.bootstrapAllowlist.workloads | default dict) $explicit) (not (has $explicit $operator)) .Values.router.nginx.image.digest .Values.image.digest -}}
{{- fail (printf "router.attest.expectedWorkload=%s names a nriImagePolicy.bootstrapAllowlist.workloads entry that does not list both router.nginx.image.digest and image.digest, so the router pod cannot match it" $explicit) -}}
{{- end -}}
{{- if $seeded -}}
{{ include "c8s.routerEntry" (dict "root" . "expectedWorkload" (include "router.expectedWorkload" .)) }}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "c8s.allowlistSeedJSON" -}}
{{- $workloads := dict -}}
{{- $pinnedDigests := include "c8s.argvPinnedDigests" . | fromJsonArray -}}
{{- range $digest, $image := (include "c8s.imageAllowlist" . | fromJson) -}}
{{- if not (has $digest $pinnedDigests) -}}
{{- $name := include "c8s.digestWorkloadName" (dict "digest" $digest "image" $image) -}}
{{- $container := dict "digest" $digest "image" $image "mounts" (dict "policy" "any") "command" (dict "policy" "any") "args" (dict "policy" "any") "env" (dict "policy" "any") -}}
{{- $_ := set $workloads $name (dict "label" $image "initContainers" list "containers" (list $container)) -}}
{{- end -}}
{{- end -}}
{{- range $name, $entry := (include "c8s.argvPinnedEntries" . | fromJson) -}}
{{- $_ := set $workloads $name $entry -}}
{{- end -}}
{{- with (include "c8s.routerWorkload" .) -}}
{{- $_ := set $workloads (include "c8s.routerWorkloadName" $) (fromJson .) -}}
{{- end -}}
{{- range $name, $entry := (.Values.nriImagePolicy.bootstrapAllowlist.workloads | default dict) -}}
{{- $_ := set $workloads $name $entry -}}
{{- end -}}
{{ dict "schema" "c8s.allowlist/v1" "workloads" $workloads | toJson }}
{{- end -}}
