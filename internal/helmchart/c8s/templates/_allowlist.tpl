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
{{- $component := dict "name" $c.valuePath "image" $img "enabled" $enabled "cdsExempt" $c.cdsExempt "argvPinned" (get $c "argvPinned" | default false) "entrypoint" (get $c "entrypoint" | default list) "denyBelow" (get $c "denyBelow" | default list) -}}
{{- if hasKey $c "imageEnv" -}}{{- $_ := set $component "imageEnv" (get $c "imageEnv" | default dict) -}}{{- end -}}
{{- $out = append $out $component -}}
{{- end -}}
{{ $out | toJson }}
{{- end -}}

{{/* The chart-deployed system images the seed and the plugin base admit, as
     digest -> {image, entrypoint, mounts, containers}. Each is admitted
     pinned to its entrypoint (c8s.componentContainers): the executable is
     the image's own, the arguments are per-pod, the mounts are confined
     (c8s.componentMounts) and the environment is matched by name. A derived
     component without an entrypoint, denyBelow list or imageEnv fails the
     render: an entry left at any command would admit the image under a
     shell or a mounted binary, and one with no denied path would let a
     volume replace the code its entrypoint loads. */ -}}
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
{{- $nginx := dict "name" "router.nginx" "entrypoint" .Values.router.nginx.entrypoint "denyBelow" .Values.router.nginx.denyBelow -}}
{{- if hasKey .Values.router.nginx "imageEnv" -}}{{- $_ := set $nginx "imageEnv" (.Values.router.nginx.imageEnv | default dict) -}}{{- end -}}
{{- $_ := set $digests $lbImg.digest (include "c8s.componentEntry" (dict "root" $root "component" $nginx "repository" $lbImg.repository "digest" $lbImg.digest) | fromJson) -}}
{{- end -}}
{{- end -}}
{{ $digests | toJson }}
{{- end -}}

{{/* One c8s.imageAllowlist value for a component of c8s.components. */ -}}
{{- define "c8s.componentEntry" -}}
{{- $image := printf "%s@%s" .repository .digest -}}
{{- $mounts := include "c8s.componentMounts" (dict "root" .root "name" (get .component "name") "denyBelow" (get .component "denyBelow")) | fromJson -}}
{{- $containers := include "c8s.componentContainers" (dict "root" .root "component" .component "digest" .digest "image" $image "mounts" $mounts) | fromJsonArray -}}
{{ dict "image" $image "entrypoint" (get .component "entrypoint") "mounts" $mounts "containers" $containers | toJson }}
{{- end -}}

{{/* The variables the runtime adds to every component container beside the
     image's and the chart's. containerd's CRI plugin adds HOSTNAME
     (internal/cri/server/container_create.go, containerd v2.1). With service
     links off, the kubelet adds only the variables of the default
     namespace's kubernetes Service (getServiceEnvVarMap in
     pkg/kubelet/kubelet_pods.go and FromServices in pkg/kubelet/envvars,
     unchanged from Kubernetes v1.34 to v1.36), whose port kube-apiserver
     fixes at 443
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
     subcommand, args any, mounts confined (c8s.componentMounts), env
     matched. Admission is the union across them. */ -}}
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
{{- $containers = append $containers (dict "digest" $.digest "image" $.image "mounts" $.mounts "command" $command "args" (dict "policy" "any") "env" $env) -}}
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

{{/* The confined mount policy of a component entry, as JSON: denyBelow from
     c8sComponents (router.nginx.denyBelow for nginx), and as unconfined the
     destinations where the chart itself mounts a writable host path, a PVC,
     or a ConfigMap, whose storage the node can vouch for only on a C8s node
     image. Keep each list in step with the component's templates; the chart
     tests check every rendered mount against it. */ -}}
{{- define "c8s.componentMounts" -}}
{{- if not .denyBelow -}}
{{- fail (printf "c8sComponents entry %s has no denyBelow: the derived allowlist entry must keep volumes off the code its entrypoint loads" .name) -}}
{{- end -}}
{{- $v := .root.Values -}}
{{- $runtimeDir := $v.nriImagePolicy.hostPaths.runtimeDir -}}
{{- $unconfined := list -}}
{{- if eq .name "image" -}}
{{- /* operator and allowlist-proxy config; attest-proxy config and its socket directory */ -}}
{{- $unconfined = list "/etc/c8s-measurements" "/etc/attestation-api" $runtimeDir -}}
{{- else if eq .name "cds.image" -}}
{{- /* also the attest-proxy socket directory, a read-only hostPath kubelet binds recursively */ -}}
{{- $unconfined = list "/data" "/etc/cds" "/etc/cds-operator-keys" "/etc/c8s-measurements" $runtimeDir -}}
{{- else if eq .name "attestationApi.image" -}}
{{- $unconfined = list "/etc/attestation-api" -}}
{{- if $v.attestationApi.teeDevices.sevGuest -}}{{- $unconfined = append $unconfined "/dev/sev-guest" -}}{{- end -}}
{{- if $v.attestationApi.teeDevices.tdxGuest -}}{{- $unconfined = append $unconfined "/sys/kernel/config" -}}{{- end -}}
{{- if $v.attestationApi.teeDevices.tpm -}}{{- $unconfined = concat $unconfined (list "/dev/tpm0" "/dev/tpmrm0") -}}{{- end -}}
{{- else if eq .name "armtlsMesh.image" -}}
{{- $unconfined = list "/run/xtables.lock" "/etc/c8s-measurements" $runtimeDir -}}
{{- else if eq .name "volumed.image" -}}
{{- /* /sys and a v1 /cgroup hold nested mounts, so their read-only binds are not recursive */ -}}
{{- $unconfined = list $v.volumed.hostPaths.kubeletRoot "/dev" "/sys" "/cgroup" $runtimeDir -}}
{{- else if eq .name "router.nginx" -}}
{{- $unconfined = list "/etc/nginx/nginx.conf" (include "router.tlsSnippetDir" .root) -}}
{{- end -}}
{{- /* The plugin and CDS reject an unclean path at load; fail the render instead. */ -}}
{{- range $p := concat .denyBelow $unconfined -}}
{{- if or (not (kindIs "string" $p)) (not (isAbs $p)) (ne (clean $p) $p) -}}
{{- fail (printf "%s mount path %v is not a clean absolute path (denyBelow, or a host path value such as nriImagePolicy.hostPaths.runtimeDir)" $.name $p) -}}
{{- end -}}
{{- end -}}
{{- $mounts := dict "policy" "confined" "denyBelow" .denyBelow -}}
{{- if $unconfined -}}{{- $_ := set $mounts "unconfined" (uniq $unconfined | sortAlpha) -}}{{- end -}}
{{ $mounts | toJson }}
{{- end -}}

{{/* Operator entries that pin at most the command — command any or exact,
     args any, mounts any or confined, env any or match — as digest ->
     {image, containers}, each container the base form of one such entry
     with its mount policy kept. These can start a component before CDS is
     reachable, so they feed the base and cover a component for the render
     guard. An entry that pins args, env exact, or mounts deny or exact, is
     seed-only. */ -}}
{{- define "c8s.openArgsEntries" -}}
{{- $digests := dict -}}
{{- range $name, $entry := (.Values.nriImagePolicy.bootstrapAllowlist.workloads | default dict) -}}
{{- range $c := concat (default list $entry.initContainers) (default list $entry.containers) -}}
{{- $command := dig "command" "policy" "" $c -}}
{{- $env := dig "env" "policy" "any" $c -}}
{{- $mounts := default (dict "policy" "deny") $c.mounts -}}
{{- if and (or (eq $command "any") (eq $command "exact")) (eq (dig "args" "policy" "" $c) "any") (or (eq $env "any") (eq $env "match")) (has (get $mounts "policy") (list "any" "confined")) -}}
{{- $container := dict "digest" $c.digest "mounts" $mounts "command" (dict "policy" "any") "args" (dict "policy" "any") -}}
{{- if eq $command "exact" -}}
{{- $argv := dig "command" "argv" list $c -}}
{{- if not $argv -}}
{{- fail (printf "nriImagePolicy.bootstrapAllowlist.workloads entry %s pins %s to an exact command with no argv" $name $c.digest) -}}
{{- end -}}
{{- $_ := set $container "command" (dict "policy" "exact" "argv" $argv) -}}
{{- end -}}
{{- if eq $env "match" -}}{{- $_ := set $container "env" $c.env -}}{{- end -}}
{{- $prior := get $digests $c.digest | default (dict "image" (default $entry.label $c.image | default "") "containers" list) -}}
{{- $_ := set $container "image" (get $prior "image") -}}
{{- if not (has $container (get $prior "containers")) -}}
{{- $_ := set $prior "containers" (append (get $prior "containers") $container) -}}
{{- end -}}
{{- $_ := set $digests $c.digest $prior -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{ $digests | toJson }}
{{- end -}}

{{/* "true" when the mount policy of the base container .container admits
     every table .mounts does: any, or the same confined policy. */ -}}
{{- define "c8s.admitsMounts" -}}
{{- $policy := get .container "mounts" -}}
{{- if or (eq (get $policy "policy") "any") (eq ($policy | toJson) (.mounts | toJson)) -}}true{{- end -}}
{{- end -}}

{{/* "true" when the base container .container admits every invocation of
     .entrypoint: its command is any or a prefix of the entrypoint, and its
     env is any. */ -}}
{{- define "c8s.coversEntrypoint" -}}
{{- $command := get .container "command" -}}
{{- $pin := get $command "argv" | default list -}}
{{- $ok := and (not (hasKey .container "env")) (le (len $pin) (len .entrypoint)) -}}
{{- range $i, $tok := $pin -}}{{- if and $ok (ne $tok (index $.entrypoint $i)) -}}{{- $ok = false -}}{{- end -}}{{- end -}}
{{- if $ok -}}true{{- end -}}
{{- end -}}

{{/* "true" when the base container .container starts .entrypoint: its
     command is any or a prefix of the entrypoint, whatever its env. */ -}}
{{- define "c8s.startsEntrypoint" -}}
{{- include "c8s.coversEntrypoint" (dict "container" (omit .container "env") "entrypoint" .entrypoint) -}}
{{- end -}}

{{/* The plugin boot base, as allowlist workloads keyed by DigestEntryName:
     the chart's system images pinned to their entrypoints, and every
     container an operator entry admits with open args (c8s.openArgsEntries).
     The boot config excludes argv-pinned images, which are admitted by the
     served seed. */ -}}
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
{{- /* Operator open-args containers for the same digest are admitted beside
       the component's, so neither the component nor the operator's
       invocations are refused on a cold node. One that admits every
       invocation of the entrypoint with any env, and every mount table the
       component's do (any, or the same policy), replaces the component's. */ -}}
{{- if hasKey $openArgs $digest -}}
{{- $operator := get (get $openArgs $digest) "containers" -}}
{{- $wider := false -}}
{{- range $o := $operator -}}
{{- if and (include "c8s.coversEntrypoint" (dict "container" $o "entrypoint" (get $entry "entrypoint"))) (include "c8s.admitsMounts" (dict "container" $o "mounts" (get $entry "mounts"))) -}}{{- $wider = true -}}{{- end -}}
{{- end -}}
{{- if $wider -}}{{- $containers = $operator -}}{{- else -}}{{- $containers = concat $containers $operator -}}{{- end -}}
{{- end -}}
{{- $_ := set $workloads $name (dict "label" $image "initContainers" list "containers" $containers) -}}
{{- end -}}
{{- end -}}
{{- range $digest, $entry := $openArgs -}}
{{- if and (not (has $digest $pinnedDigests)) (not (hasKey $components $digest)) -}}
{{- $image := get $entry "image" -}}
{{- $name := include "c8s.digestWorkloadName" (dict "digest" $digest "image" $image) -}}
{{- $_ := set $workloads $name (dict "label" $image "initContainers" list "containers" (get $entry "containers")) -}}
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
{{- $dataDir := toString .Values.rke2.localPathHelper.dataDir -}}
{{- if or (not (isAbs $dataDir)) (ne (clean $dataDir) $dataDir) -}}
{{- fail (printf "rke2.localPathHelper.dataDir %q is not a clean absolute path" $dataDir) -}}
{{- end -}}
{{- $mounts := dict "policy" "confined" "denyBelow" (list "/bin" "/sbin" "/usr" "/lib" "/lib64" "/etc/ld.so.preload" "/etc/ld.so.cache" "/etc/ld.so.conf" "/etc/ld.so.conf.d") "unconfined" (list "/script" $dataDir) -}}
{{- range $path := list "/script/setup" "/script/teardown" -}}
{{- $containers = append $containers (dict "digest" $img.digest "image" $ref "mounts" $mounts "command" (dict "policy" "exact" "argv" (list "/bin/sh" $path)) "args" (dict "policy" "any")) -}}
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
