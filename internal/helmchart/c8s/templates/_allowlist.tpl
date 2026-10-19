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

{{/* The command of a container running a component image: the entrypoint
     c8sComponents declares for valuePath, as a JSON list. Spelling it out
     makes the argv the allowlist pins independent of the image's own
     ENTRYPOINT and CMD. Takes root and valuePath. */ -}}
{{- define "c8s.entrypoint" -}}
{{- range $c := .root.Values.c8sComponents -}}
{{- if eq $c.valuePath $.valuePath -}}{{- $c.entrypoint | toJson -}}{{- end -}}
{{- end -}}
{{- end -}}

{{/* The chart-deployed system images the seed and the plugin base admit, as
     digest -> {image, entrypoint, imageEnv}. Each container that runs one is
     pinned to its exact argv and mount table and matched on its env
     (c8s.componentShapes); the entrypoint is the command prefix of a
     container that runs the image's own, and imageEnv the image config's
     Env. A derived component without either fails the render. */ -}}
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
{{- if not (hasKey $c "imageEnv") -}}
{{- fail (printf "c8sComponents entry %s has no imageEnv: the derived allowlist entry must match the image's environment" (get $c "name")) -}}
{{- end -}}
{{- $_ := set $digests (get $img "digest") (dict "image" (printf "%s@%s" (get $img "repository") (get $img "digest")) "entrypoint" (get $c "entrypoint") "imageEnv" (get $c "imageEnv")) -}}
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
{{- if not (hasKey $cds "imageEnv") -}}
{{- fail "c8sComponents entry cds.image has no imageEnv: the CDS self-entry must match the image's environment" -}}
{{- end -}}
{{- $_ := set $digests $cdsImg.digest (dict "image" (printf "%s@%s" $cdsImg.repository $cdsImg.digest) "entrypoint" (get $cds "entrypoint") "imageEnv" (get $cds "imageEnv")) -}}
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
{{- if not (hasKey .Values.router.nginx "imageEnv") -}}
{{- fail "router.nginx.imageEnv is required: the nginx self-entry must match the image's environment" -}}
{{- end -}}
{{- $_ := set $digests $lbImg.digest (dict "image" (printf "%s@%s" $lbImg.repository $lbImg.digest) "entrypoint" .Values.router.nginx.entrypoint "imageEnv" (.Values.router.nginx.imageEnv | default dict)) -}}
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
     them, and env matched over the names the container launches with
     (c8s.componentEnv). Takes name, spec, pins (digest -> entrypoint), envs
     (digest -> imageEnv) and refs (digest -> image reference). See
     ../helpers/allowlist/README.md#component-shapes. */ -}}
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
{{- $command := include "c8s.kubeletExpand" (dict "argv" (default list $c.command) "where" $where) | fromJsonArray -}}
{{- $args := include "c8s.kubeletExpand" (dict "argv" (default list $c.args) "where" $where) | fromJsonArray -}}
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
{{- $env := include "c8s.componentEnv" (dict "imageEnv" (get $.envs $digest) "container" $c "where" $where) | fromJson -}}
{{- $mountPolicy := dict "policy" "deny" -}}
{{- if $mounts -}}{{- $mountPolicy = dict "policy" "exact" "rules" $mounts -}}{{- end -}}
{{- $shape := dict "digest" $digest "image" (get $.refs $digest) "command" $commandPolicy "args" $argsPolicy "mounts" $mountPolicy "env" $env -}}
{{- if not (has $shape $out) -}}{{- $out = append $out $shape -}}{{- end -}}
{{- end -}}
{{- end -}}
{{ $out | toJson }}
{{- end -}}

{{/* The argv the kubelet hands the runtime: $$ becomes $, scanning left to
     right as the kubelet does. A $(NAME) reference fails the render: the
     kubelet expands it from env, envFrom or a service variable, values the
     pinned argv cannot know. Escape it as $$(NAME) and expand it in the
     binary instead. */ -}}
{{- define "c8s.kubeletExpand" -}}
{{- $out := list -}}
{{- range $token := .argv -}}
{{- $token = toString $token -}}
{{- range $ref := regexFindAll `\$\$|\$\([^)]*\)` $token -1 -}}
{{- if ne $ref "$$" -}}
{{- $name := trimSuffix ")" (trimPrefix "$(" $ref) -}}
{{- fail (printf "%s references %s in its argv, which the kubelet may expand; the allowlist pins the argv exactly, so escape it as $$(%s)" $.where $ref $name) -}}
{{- end -}}
{{- end -}}
{{- $out = append $out (regexReplaceAll `\$(\$)` $token "${1}") -}}
{{- end -}}
{{ $out | toJson }}
{{- end -}}

{{/* The variables the runtime adds to every component container beside the
     image's and the pod spec's. containerd's CRI plugin adds HOSTNAME
     (internal/cri/server/container_create.go, containerd v2.1). With service
     links off, the kubelet adds only the variables of the default
     namespace's kubernetes Service (getServiceEnvVarMap in
     pkg/kubelet/kubelet_pods.go and FromServices in pkg/kubelet/envvars),
     whose port kube-apiserver fixes at 443 (APIServerServicePort in
     cmd/kube-apiserver/app). */ -}}
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

{{/* The env match for one component container: every variable it launches
     with, each source overriding the one before as the runtime applies them:
     containerd's HOSTNAME, the image's variables (imageEnv, pinned exact),
     the kubelet's, then the container's env (container_create.go in
     containerd's CRI plugin, makeEnvironmentVariables in
     pkg/kubelet/kubelet_pods.go). containerd sets a default PATH when the
     image sets none (oci.WithDefaultPathEnv). A constant value is pinned
     exact and a valueFrom is matched present. envFrom, an optional reference
     and a $(NAME) reference fail the render: the names or values would
     depend on objects the chart does not render. Loader variables are never
     listed, so match refuses them. Takes imageEnv, container and where. */ -}}
{{- define "c8s.componentEnv" -}}
{{- $runtime := include "c8s.runtimeEnv" . | fromJson -}}
{{- $variables := dict "HOSTNAME" (get $runtime "HOSTNAME") -}}
{{- if not (hasKey .imageEnv "PATH") -}}
{{- $_ := set $variables "PATH" (dict "exact" "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin") -}}
{{- end -}}
{{- range $name, $value := .imageEnv -}}{{- $_ := set $variables $name (dict "exact" (toString $value)) -}}{{- end -}}
{{- range $name, $matcher := omit $runtime "HOSTNAME" -}}{{- $_ := set $variables $name $matcher -}}{{- end -}}
{{- if .container.envFrom -}}
{{- fail (printf "%s sets envFrom: the allowlist matches env by name, so list each variable under env" .where) -}}
{{- end -}}
{{- range $e := (default list .container.env) -}}
{{- $where := printf "%s env %s" $.where $e.name -}}
{{- if $e.valueFrom -}}
{{- if or (dig "secretKeyRef" "optional" false $e.valueFrom) (dig "configMapKeyRef" "optional" false $e.valueFrom) -}}
{{- fail (printf "%s is optional: the allowlist matches env by name, so the variable must always be set" $where) -}}
{{- end -}}
{{- $_ := set $variables $e.name (dict "present" true) -}}
{{- else -}}
{{- $value := include "c8s.kubeletExpand" (dict "argv" (list (toString (default "" $e.value))) "where" $where) | fromJsonArray | first -}}
{{- $_ := set $variables $e.name (dict "exact" $value) -}}
{{- end -}}
{{- end -}}
{{ dict "policy" "match" "variables" $variables | toJson }}
{{- end -}}

{{/* The exact mount rules for one container. containerd resolves symlinks
     in a hostPath source, so a source under /var/run, a symlink to /run on
     some nodes and not on others, has no single spelling the node reports:
     host paths must name /run. */ -}}
{{- define "c8s.mountRules" -}}
{{- $rules := list -}}
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
{{- if hasKey $v "hostPath" -}}
{{- $source := toString $v.hostPath.path -}}
{{- if or (not (isAbs $source)) (ne (clean $source) $source) -}}{{- fail (printf "%s host path %q is not a clean absolute path" $where $source) -}}{{- end -}}
{{- if or (eq $source "/var/run") (hasPrefix "/var/run/" $source) -}}{{- fail (printf "%s host path %q sits under /var/run: name it under /run" $where $source) -}}{{- end -}}
{{- $rule = dict "destination" $dest "kind" "host" "source" $source -}}
{{- if $m.readOnly -}}{{- $_ := set $rule "readOnly" true -}}{{- end -}}
{{- else if hasKey $v "emptyDir" -}}
{{- $rule = dict "destination" $dest "kind" "emptyDir" -}}
{{- else if or (hasKey $v "configMap") (hasKey $v "secret") (hasKey $v "projected") (hasKey $v "downwardAPI") (hasKey $v "persistentVolumeClaim") -}}
{{- if not (hasPrefix "/mnt/c8s-data/" $dest) -}}
{{- fail (printf "%s mounts a ConfigMap, Secret or PVC at %q: data volumes must sit under /mnt/c8s-data/" $where $dest) -}}
{{- end -}}
{{- $rule = dict "destination" $dest "kind" "data" -}}
{{- else -}}
{{- fail (printf "%s has a volume source the allowlist cannot pin" $where) -}}
{{- end -}}
{{- $rules = append $rules $rule -}}
{{- end -}}
{{ $rules | toJson }}
{{- end -}}

{{/* The shapes of the sidecars the webhook injects with the C8s image
     (internal/webhook): each pinned to its invocation with args open, since
     the SAN and file paths are per pod, to a fixed mount table, and to the
     env names getCertEnv gives it, matched present since they differ per
     pod. The discovery and reload-watch mounts are optional, so each
     combination is its own shape. The plugin's own inventory socket mount
     observes as platform, so no shape names it. The destinations match
     the webhook's defaults, which pods can no longer move. Takes root, digest,
     image and imageEnv. */ -}}
{{- define "c8s.injectedShapes" -}}
{{- $certs := dict "destination" "/etc/c8s/certs" "kind" "emptyDir" -}}
{{- $discovery := dict "destination" "/run/c8s/discovery" "kind" "emptyDir" -}}
{{- $reload := dict "destination" "/mnt/c8s-data/c8s-reload-watch" "kind" "data" -}}
{{- $secrets := dict "destination" "/run/c8s/secrets" "kind" "emptyDir" -}}
{{- $podEnv := list -}}
{{- range $name := list "C8S_WORKLOAD_ID" "C8S_POD_NAME" "C8S_POD_UID" "HOST_IP" -}}
{{- $podEnv = append $podEnv (dict "name" $name "valueFrom" (dict "fieldRef" dict)) -}}
{{- end -}}
{{- $sidecars := list
      (dict "mode" "get-cert" "fixed" (list $certs) "optional" (list $discovery $reload) "env" $podEnv)
      (dict "mode" "probe-file" "fixed" (list $certs) "optional" (list $discovery) "env" list)
      (dict "mode" "get-secret" "fixed" (list $certs $secrets) "optional" (list $discovery) "env" $podEnv)
      (dict "mode" "get-volume" "fixed" (list $certs) "optional" (list $discovery) "env" $podEnv) -}}
{{- $out := list -}}
{{- range $s := $sidecars -}}
{{- $tables := list (get $s "fixed") -}}
{{- range $m := get $s "optional" -}}
{{- $grown := list -}}
{{- range $t := $tables -}}{{- $grown = append (append $grown $t) (append $t $m) -}}{{- end -}}
{{- $tables = $grown -}}
{{- end -}}
{{- $env := include "c8s.componentEnv" (dict "imageEnv" $.imageEnv "container" (dict "env" (get $s "env")) "where" (printf "injected %s" (get $s "mode"))) | fromJson -}}
{{- range $t := $tables -}}
{{- $out = append $out (dict "digest" $.digest "image" $.image "command" (dict "policy" "exact" "argv" (list "/c8s" (get $s "mode"))) "args" (dict "policy" "any") "mounts" (dict "policy" "exact" "rules" $t) "env" $env) -}}
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
{{- $envs := dict -}}
{{- $refs := dict -}}
{{- range $digest, $entry := $components -}}
{{- $_ := set $pins $digest (get $entry "entrypoint") -}}
{{- $_ := set $envs $digest (get $entry "imageEnv") -}}
{{- $_ := set $refs $digest (get $entry "image") -}}
{{- end -}}
{{- $shapes := dict -}}
{{- range $pod := (include "c8s.componentPods" . | fromJsonArray) -}}
{{- range $c := (include "c8s.podShapes" (dict "name" (get $pod "name") "spec" (get $pod "spec") "pins" $pins "envs" $envs "refs" $refs) | fromJsonArray) -}}
{{- $list := get $shapes (get $c "digest") | default list -}}
{{- if not (has $c $list) -}}{{- $_ := set $shapes (get $c "digest") (append $list $c) -}}{{- end -}}
{{- end -}}
{{- end -}}
{{- $operator := default "" .Values.image.digest -}}
{{- if hasKey $components $operator -}}
{{- $injected := include "c8s.injectedShapes" (dict "root" . "digest" $operator "image" (get $refs $operator) "imageEnv" (get $envs $operator)) | fromJsonArray -}}
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

{{/* "true" when an operator-written container admits a component shape:
     its command any or a prefix of the shape's argv, its args admitting the
     rest (any for a shape whose args are open), its mounts any or the shape's
     rule set, and its env any or a match over the shape's names whose exact
     matchers pin the values the shape pins. Feeds the coverage guard
     (validations.yaml). */ -}}
{{- define "c8s.admitsShape" -}}
{{- $c := .container -}}
{{- $shape := .shape -}}
{{- $argv := concat (get (get $shape "command") "argv") (dig "args" "argv" list $shape) -}}
{{- $ok := true -}}
{{- $rest := $argv -}}
{{- $command := dig "command" "policy" "" $c -}}
{{- if eq $command "exact" -}}
{{- $pin := dig "command" "argv" list $c -}}
{{- if and (le (len $pin) (len $argv)) (eq (slice $argv 0 (len $pin) | toJson) ($pin | toJson)) -}}
{{- $rest = slice $argv (len $pin) -}}
{{- else -}}
{{- $ok = false -}}
{{- end -}}
{{- else if ne $command "any" -}}
{{- $ok = false -}}
{{- end -}}
{{- $args := dig "args" "policy" "deny" $c -}}
{{- if eq (dig "args" "policy" "" $shape) "any" -}}
{{- if ne $args "any" -}}{{- $ok = false -}}{{- end -}}
{{- else if eq $args "exact" -}}
{{- if ne ($rest | toJson) (dig "args" "argv" list $c | toJson) -}}{{- $ok = false -}}{{- end -}}
{{- else if eq $args "deny" -}}
{{- if $rest -}}{{- $ok = false -}}{{- end -}}
{{- else if ne $args "any" -}}
{{- $ok = false -}}
{{- end -}}
{{- $mounts := dig "mounts" "policy" "deny" $c -}}
{{- if ne $mounts "any" -}}
{{- $want := dict -}}
{{- range $r := (dig "mounts" "rules" list $shape) -}}{{- $_ := set $want $r.destination (list $r.kind (default "" $r.source) (toString (default false $r.readOnly))) -}}{{- end -}}
{{- $have := dict -}}
{{- range $r := (dig "mounts" "rules" list $c) -}}{{- $_ := set $have (toString $r.destination) (list (toString $r.kind) (default "" $r.source) (toString (default false $r.readOnly))) -}}{{- end -}}
{{- if or (not (has $mounts (list "exact" "deny"))) (ne ($want | toJson) ($have | toJson)) -}}{{- $ok = false -}}{{- end -}}
{{- end -}}
{{- $env := dig "env" "policy" "any" $c -}}
{{- if eq $env "match" -}}
{{- $want := dig "env" "variables" dict $shape -}}
{{- $have := dig "env" "variables" dict $c -}}
{{- if ne (keys $want | sortAlpha | toJson) (keys $have | sortAlpha | toJson) -}}{{- $ok = false -}}{{- end -}}
{{- range $name, $m := $have -}}
{{- if and (hasKey $m "exact") (ne (toString (get $m "exact")) (toString (dig $name "exact" "" $want))) -}}{{- $ok = false -}}{{- end -}}
{{- if and (hasKey $m "exact") (not (hasKey (get $want $name | default dict) "exact")) -}}{{- $ok = false -}}{{- end -}}
{{- end -}}
{{- else if ne $env "any" -}}
{{- $ok = false -}}
{{- end -}}
{{- if $ok -}}true{{- end -}}
{{- end -}}

{{/* The base container for an operator open-args entry pinned to an
     entrypoint: command pinned, args and mounts any. */ -}}
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
{{- with get (get $c "image") "digest" -}}{{- $componentDigests = append $componentDigests (lower .) -}}{{- end -}}
{{- end -}}
{{- with .Values.router.nginx.image.digest -}}{{- $componentDigests = append $componentDigests (lower .) -}}{{- end -}}
{{- $digests := dict -}}
{{- range $name, $entry := (.Values.nriImagePolicy.bootstrapAllowlist.workloads | default dict) -}}
{{- range $c := concat (default list $entry.initContainers) (default list $entry.containers) -}}
{{- $command := dig "command" "policy" "" $c -}}
{{- $open := and (eq (dig "args" "policy" "" $c) "any") (eq (dig "env" "policy" "any" $c) "any") (eq (dig "mounts" "policy" "deny" $c) "any") -}}
{{- $digest := lower (toString $c.digest) -}}
{{- if and (or (eq $command "any") (eq $command "exact")) (not $open) (has $digest $componentDigests) -}}
{{- $_ := set $digests $digest (append (get $digests $digest | default list) $c) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{ $digests | toJson }}
{{- end -}}

{{/* The plugin boot base, as allowlist workloads keyed by entry name: the
     chart's component shapes (c8s.componentShapes) under
     c8s.shapeWorkloadName, and, under c8s.digestWorkloadName, every digest an
     operator entry admits with open args (c8s.openArgsEntries) under the
     command that entry pins or under any, with the operator's own entries for
     a component digest (c8s.pinnedComponentEntries). Admission is the union
     across entries, so keeping the operator's containers apart from the
     chart's admits the same launches and leaves each entry's per-variable
     evidence budget to its own containers. The boot config excludes
     argv-pinned images, which are admitted by the served seed. */ -}}
{{- define "c8s.baseWorkloads" -}}
{{- $workloads := dict -}}
{{- $pinnedDigests := include "c8s.argvPinnedDigests" . | fromJsonArray -}}
{{- $excluded := list -}}
{{- range $d := $pinnedDigests -}}{{- $excluded = append $excluded (lower $d) -}}{{- end -}}
{{- range $digest, $entry := (include "c8s.componentShapes" . | fromJson) -}}
{{- if not (has (lower $digest) $excluded) -}}
{{- $name := include "c8s.shapeWorkloadName" (dict "digest" $digest "image" (get $entry "image") "containers" (get $entry "containers")) -}}
{{- $_ := set $workloads $name (dict "label" (get $entry "image") "initContainers" list "containers" (get $entry "containers")) -}}
{{- end -}}
{{- end -}}
{{- /* Keyed by the lowercased digest, as the entry name is: two spellings of
       one digest are one entry. */ -}}
{{- $images := dict -}}
{{- $containers := dict -}}
{{- range $digest, $entry := (include "c8s.openArgsEntries" . | fromJson) -}}
{{- $key := lower $digest -}}
{{- if not (hasKey $images $key) -}}{{- $_ := set $images $key (get $entry "image") -}}{{- end -}}
{{- $container := include "c8s.openArgsContainer" (dict "digest" $digest "entry" $entry) | fromJson -}}
{{- $_ := set $containers $key (append (get $containers $key | default list) $container) -}}
{{- end -}}
{{- range $digest, $list := (include "c8s.pinnedComponentEntries" . | fromJson) -}}
{{- if not (hasKey $images $digest) -}}{{- $_ := set $images $digest (default "" (get (first $list) "image")) -}}{{- end -}}
{{- $_ := set $containers $digest (concat (get $containers $digest | default list) $list) -}}
{{- end -}}
{{- range $digest, $list := $containers -}}
{{- if not (has $digest $excluded) -}}
{{- $image := get $images $digest -}}
{{- $_ := set $workloads (include "c8s.digestWorkloadName" (dict "digest" $digest "image" $image)) (dict "label" $image "initContainers" list "containers" $list) -}}
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
{{- $base := .image | splitList "@" | first | splitList "/" | last | splitList ":" | first | trunc (int (default 50 .baseMax)) -}}
{{- if not (regexMatch "^[A-Za-z0-9][A-Za-z0-9._-]*$" $base) -}}{{- $base = "image" -}}{{- end -}}
{{- printf "%s-%s" $base (.digest | trimPrefix "sha256:" | lower | trunc 12) -}}
{{- end -}}

{{/* A generated entry's name: c8s.digestWorkloadName with its image segment
     cut to 41 characters, then the first 8 hex of sha256 over its
     containers without their image labels, which matching ignores, 63
     characters at most. A configuration change that alters
     an argv, env or mount table names a new entry, which CDS's seeding adds
     beside the old one (it retires an old one only when it left a
     component's args, mounts or env open). See
     ../helpers/allowlist/README.md#entry-names. */ -}}
{{- define "c8s.shapeWorkloadName" -}}
{{- $matched := list -}}
{{- range $c := .containers -}}{{- $matched = append $matched (omit $c "image") -}}{{- end -}}
{{- printf "%s-%s" (include "c8s.digestWorkloadName" (dict "digest" .digest "image" .image "baseMax" 41)) ($matched | toJson | sha256sum | trunc 8) -}}
{{- end -}}

{{/* The seed entry name of CDS's own shape, or "" when CDS is not
     digest-pinned. */ -}}
{{- define "c8s.cdsShapeName" -}}
{{- $digest := .Values.cds.image.digest -}}
{{- with get (include "c8s.componentShapes" . | fromJson) (default "" $digest) -}}
{{- include "c8s.shapeWorkloadName" (dict "digest" $digest "image" (get . "image") "containers" (get . "containers")) -}}
{{- end -}}
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
{{- $name := include "c8s.shapeWorkloadName" (dict "digest" $digest "image" $ref "containers" $containers) -}}
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
{{- $name := include "c8s.shapeWorkloadName" (dict "digest" $digest "image" $ref "containers" (list $container)) -}}
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
{{- $name := include "c8s.shapeWorkloadName" (dict "digest" $img.digest "image" $ref "containers" $containers) -}}
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

{{- /* Why the router entry cannot be derived, or "" when it can. Values-only,
       so router.expectedWorkload can call it. */ -}}
{{- define "c8s.routerEntryBlocker" -}}
{{- if not .Values.router.enabled -}}router.enabled is false
{{- else if not .Values.router.nginx.image.digest -}}router.nginx.image.digest is unset
{{- else if not .Values.image.digest -}}image.digest is unset
{{- /* The entry pins the c8s image's containers like its component entry,
       which deriveComponents seeds. */ -}}
{{- else if not .Values.nriImagePolicy.bootstrapAllowlist.deriveComponents -}}nriImagePolicy.bootstrapAllowlist.deriveComponents is false
{{- end -}}
{{- end -}}

{{- /* A non-empty router.attest.expectedWorkload outside c8s-router-*: the
       operator's own router entry, which replaces the seeded one. */ -}}
{{- define "c8s.routerOperatorGate" -}}
{{- $explicit := .Values.router.attest.expectedWorkload -}}
{{- if and (kindIs "string" $explicit) (not (hasPrefix "c8s-router-" $explicit)) -}}{{ $explicit }}{{- end -}}
{{- end -}}

{{- define "c8s.routerWorkloadSeeded" -}}
{{- if not (or (include "c8s.routerEntryBlocker" .) (include "c8s.routerOperatorGate" .)) -}}true{{- end -}}
{{- end -}}

{{- /* Every container of router.podSpec whose image is nginx or the c8s
       image, pinned and env-matched as c8s.podShapes pins a component's. */ -}}
{{- define "c8s.routerEntry" -}}
{{- $components := include "c8s.imageAllowlist" . | fromJson -}}
{{- $pins := dict -}}
{{- $envs := dict -}}
{{- $refs := dict -}}
{{- range $digest := list .Values.router.nginx.image.digest .Values.image.digest -}}
{{- with get $components $digest -}}
{{- $_ := set $pins $digest (get . "entrypoint") -}}
{{- $_ := set $envs $digest (get . "imageEnv") -}}
{{- $_ := set $refs $digest (get . "image") -}}
{{- end -}}
{{- end -}}
{{- $spec := include "router.podSpec" . | fromYaml -}}
{{- $volumes := default list $spec.volumes -}}
{{- $inits := list -}}
{{- $mains := list -}}
{{- range $init := list true false -}}
{{- range $c := ternary (default list $spec.initContainers) (default list $spec.containers) $init -}}
{{- $shapes := include "c8s.podShapes" (dict "name" "router" "spec" (dict "volumes" $volumes "containers" (list $c)) "pins" $pins "envs" $envs "refs" $refs) | fromJsonArray -}}
{{- if $init -}}
{{- $inits = concat $inits $shapes -}}
{{- else -}}
{{- $mains = concat $mains $shapes -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{ dict "initContainers" $inits "containers" $mains | toJson }}
{{- end -}}

{{- /* c8s-router-<12 hex of sha256 over the entry>, so a changed digest, argv
       or mount seeds a new entry. The entry's own name sits inside its argv
       (cds-attest's gate, c8s-cert's --expected-workload), so the hash renders
       the pod with routerNamePlaceholder set, under which this returns a fixed
       placeholder. */ -}}
{{- define "c8s.routerWorkloadName" -}}
{{- if hasKey . "routerNamePlaceholder" -}}<default>
{{- else -}}
{{- $ctx := dict "Values" .Values "Release" .Release "Chart" .Chart "Capabilities" .Capabilities "Template" .Template "Files" .Files "routerNamePlaceholder" true -}}
{{- printf "c8s-router-%s" (include "c8s.routerEntry" $ctx | sha256sum | trunc 12) -}}
{{- end -}}
{{- end -}}

{{- /* The entry the router pod should match: the seeded one, or the
       operator's. "" when neither. */ -}}
{{- define "c8s.routerEntryName" -}}
{{- if eq (include "c8s.routerWorkloadSeeded" .) "true" -}}
{{- include "c8s.routerWorkloadName" . -}}
{{- else -}}
{{- include "c8s.routerOperatorGate" . -}}
{{- end -}}
{{- end -}}

{{- define "c8s.allowlistSeedJSON" -}}
{{- $workloads := dict -}}
{{- $pinnedDigests := include "c8s.argvPinnedDigests" . | fromJsonArray -}}
{{- $overrides := .Values.nriImagePolicy.bootstrapAllowlist.workloads | default dict -}}
{{- range $digest, $entry := (include "c8s.componentShapes" . | fromJson) -}}
{{- if not (has $digest $pinnedDigests) -}}
{{- $image := get $entry "image" -}}
{{- $containers := get $entry "containers" -}}
{{- if not (hasKey $overrides (include "c8s.digestWorkloadName" (dict "digest" $digest "image" $image))) -}}
{{- $_ := set $workloads (include "c8s.shapeWorkloadName" (dict "digest" $digest "image" $image "containers" $containers)) (dict "label" $image "initContainers" list "containers" $containers) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- range $name, $entry := (include "c8s.argvPinnedEntries" . | fromJson) -}}
{{- $_ := set $workloads $name $entry -}}
{{- end -}}
{{- if eq (include "c8s.routerWorkloadSeeded" .) "true" -}}
{{- $_ := set $workloads (include "c8s.routerWorkloadName" .) (include "c8s.routerEntry" . | fromJson) -}}
{{- end -}}
{{- range $name, $entry := (.Values.nriImagePolicy.bootstrapAllowlist.workloads | default dict) -}}
{{- $_ := set $workloads $name $entry -}}
{{- end -}}
{{ dict "schema" "c8s.allowlist/v1" "workloads" $workloads | toJson }}
{{- end -}}
