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
     admits under any command line, keyed by its DigestEntryName, plus the
     role entries of the injected platform components. The boot config excludes
     argv-pinned images, which are admitted by the served seed. */ -}}
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
{{- range $name, $entry := (include "c8s.roleWorkloads" . | fromJson) -}}
{{- $_ := set $workloads $name $entry -}}
{{- end -}}
{{ $workloads | toJson }}
{{- end -}}

{{/* The platform-role entries of the rendered base, mirroring the measured
     base (node-guest-image/c8s/image-policy.yaml.in). The enforcer grants a
     role from the base alone, so a container on a reserved uid — an injected
     one, or one of the router pod the chart renders itself — is refused on a
     node whose base names no role for it.

     INVARIANT: each command is the image's entrypoint (cmd/c8s/Dockerfile,
     cmd/armtls-mesh/Dockerfile) plus the component's own subcommand where the
     image carries more than one, so no other subcommand of these images holds
     a role. The arguments after it are the injector's, per pod. A role rides
     on a digest the base already admits for that component's repository,
     whether it came from a component value or from a bootstrapAllowlist
     entry. */ -}}
{{- define "c8s.roleWorkloads" -}}
{{- $root := . -}}
{{- $meshRepository := include "c8s.imageRepository" .Values.armtlsMesh.image.repository -}}
{{- $credentialsRepository := include "c8s.imageRepository" .Values.image.repository -}}
{{- $nginxRepository := include "c8s.imageRepository" .Values.router.nginx.image.repository -}}
{{- $repositories := list $meshRepository $credentialsRepository $nginxRepository -}}
{{- if ne (len (uniq $repositories)) (len $repositories) -}}
{{- fail (printf "VALIDATION_ERROR kind=shared_component_repository: the mesh endpoint, the C8s components and the front door must come from distinct repositories, so each digest takes the role of what it runs; got %v" $repositories) -}}
{{- end -}}
{{- $mesh := list -}}
{{- $credentials := list -}}
{{- $nginx := list -}}
{{- range $digest, $image := (merge (include "c8s.anyArgvDigests" $root | fromJson) (include "c8s.imageAllowlist" $root | fromJson)) -}}
{{- $repository := include "c8s.imageRepository" $image -}}
{{- if eq $repository $meshRepository -}}
{{- $mesh = append $mesh (dict "digest" $digest "image" $image) -}}
{{- else if eq $repository $credentialsRepository -}}
{{- $credentials = append $credentials (dict "digest" $digest "image" $image) -}}
{{- else if eq $repository $nginxRepository -}}
{{- $nginx = append $nginx (dict "digest" $digest "image" $image) -}}
{{- end -}}
{{- end -}}
{{- $entries := dict -}}
{{- range $role := list
  (dict "name" "c8s-mesh-endpoint" "role" "mesh" "argv" (list "/app/c8s" "armtls-mesh") "images" $mesh "label" $root.Values.armtlsMesh.image.repository)
  (dict "name" "c8s-get-cert" "role" "credentials" "argv" (list "/c8s" "get-cert") "images" $credentials "label" $root.Values.image.repository)
  (dict "name" "c8s-cert-wait" "role" "credentials" "argv" (list "/c8s" "probe-file") "images" $credentials "label" $root.Values.image.repository)
  (dict "name" "c8s-get-secret" "role" "credentials" "argv" (list "/c8s" "get-secret") "images" $credentials "label" $root.Values.image.repository)
  (dict "name" "c8s-get-volume" "role" "credentials" "argv" (list "/c8s" "get-volume") "images" $credentials "label" $root.Values.image.repository)
  (dict "name" "c8s-router-nginx" "role" "router" "argv" (list "/bin/sh" "/etc/nginx/reload.sh") "images" $nginx "label" $root.Values.router.nginx.image.repository)
  (dict "name" "c8s-acme" "role" "acme" "argv" (list "/c8s" "acme") "images" $credentials "label" $root.Values.image.repository)
  (dict "name" "c8s-cds-attest" "role" "router" "argv" (list "/c8s" "cds-attest") "images" $credentials "label" $root.Values.image.repository)
  (dict "name" "c8s-allowlist-proxy" "role" "credentials" "argv" (list "/c8s" "allowlist-proxy") "images" $credentials "label" $root.Values.image.repository) -}}
{{- $containers := list -}}
{{- range $image := $role.images -}}
{{- $containers = append $containers (dict "digest" $image.digest "image" $image.image "role" $role.role "command" (dict "policy" "exact" "argv" $role.argv) "args" (dict "policy" "any") "mounts" (dict "policy" "any")) -}}
{{- end -}}
{{- if $containers -}}
{{- $_ := set $entries $role.name (dict "label" $role.label "initContainers" list "containers" $containers) -}}
{{- end -}}
{{- end -}}
{{ $entries | toJson }}
{{- end -}}

{{/* The repository an image reference names, as one canonical string: no tag,
     no digest, and Docker Hub's implicit registry and library namespace left
     off, so a reference naming them explicitly and a component value that
     omits them compare equal. */ -}}
{{- define "c8s.imageRepository" -}}
{{- $path := . | splitList "@" | first | splitList "/" -}}
{{- $repository := append (initial $path) (last $path | splitList ":" | first) | join "/" -}}
{{- $repository = regexReplaceAll "^(index\\.)?docker\\.io/" $repository "" -}}
{{- regexReplaceAll "^library/" $repository "" -}}
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

{{- define "c8s.allowlistSeedJSON" -}}
{{- $root := . -}}
{{- $workloads := dict -}}
{{- $pinnedDigests := include "c8s.argvPinnedDigests" . | fromJsonArray -}}
{{- $meshRepository := include "c8s.imageRepository" .Values.armtlsMesh.image.repository -}}
{{- range $digest, $image := (include "c8s.imageAllowlist" . | fromJson) -}}
{{- if not (has $digest $pinnedDigests) -}}
{{- $name := include "c8s.digestWorkloadName" (dict "digest" $digest "image" $image) -}}
{{- $container := dict "digest" $digest "image" $image "mounts" (dict "policy" "any") "command" (dict "policy" "any") "args" (dict "policy" "any") "env" (dict "policy" "any") -}}
{{- if eq (include "c8s.imageRepository" $image) $meshRepository -}}
{{- /* INVARIANT: equal to the mesh entry of the measured base (node-guest-image/c8s/image-policy.yaml.in) and to the container the injector builds (internal/webhook, meshContainer); env is the kubelet's, which adds the pod's service variables. */ -}}
{{- $container = dict
  "digest" $digest
  "image" $image
  "command" (dict "policy" "exact" "argv" (list "/app/c8s" "armtls-mesh"))
  "args" (dict "policy" "exact" "argv" (list
    (printf "--cert-path=%s" (include "c8s.certFile" $root))
    (printf "--key-path=%s" (include "c8s.keyFile" $root))
    (printf "--ca-path=%s" (include "c8s.caFile" $root))))
  "mounts" (dict "policy" "exact" "rules" (list (dict "destination" (include "c8s.certDir" $root) "kind" "emptyDir")))
  "env" (dict "policy" "any") -}}
{{- end -}}
{{- $_ := set $workloads $name (dict "label" $image "initContainers" list "containers" (list $container)) -}}
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
