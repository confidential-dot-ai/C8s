{{/* The component workloads this chart runs, as a JSON list of
     [name, pod spec template] for c8s.componentPods: the router alone. */}}
{{- define "worker.componentPodTemplates" -}}
{{ list (list "router" "router.podSpec") | toJson }}
{{- end -}}

{{/* The volumed DaemonSet's entry: its one container pinned and env-matched
     as c8s.podShapes pins a component's. `c8s worker component-set` publishes
     it as the release's node service. */}}
{{- define "worker.volumedEntry" -}}
{{- $component := include "c8s.component" (dict
  "components" (include "c8s.components" . | fromJsonArray)
  "name" "volumed.image"
) | fromJson -}}
{{- $digest := $component.image.digest -}}
{{- $shapes := include "c8s.podShapes" (dict
  "name" "volumed"
  "spec" (include "volumed.podSpec" . | fromYaml)
  "pins" (dict $digest $component.entrypoint)
  "envs" (dict $digest $component.imageEnv)
  "refs" (dict $digest (include "volumed.image" .))
) | fromJsonArray -}}
{{ dict "containers" $shapes | toJson }}
{{- end -}}

{{- define "worker.volumedWorkloadName" -}}
{{- printf "c8s-volumed-%s" (include "worker.volumedEntry" . | sha256sum | trunc 12) -}}
{{- end -}}

{{/* The seed a worker cluster's Trust Authority serves: the component shapes
     of the router and of the sidecars the webhook injects, the router entry
     and the volumed DaemonSet's. */}}
{{- define "worker.allowlistSeedJSON" -}}
{{- $shapes := include "c8s.componentShapes" (dict "root" . "templates" (include "worker.componentPodTemplates" .)) -}}
{{- $workloads := include "c8s.shapeWorkloads" $shapes | fromJson -}}
{{- $_ := set $workloads (include "c8s.routerWorkloadName" .) (include "c8s.routerEntry" . | fromJson) -}}
{{- $_ := set $workloads (include "worker.volumedWorkloadName" .) (include "worker.volumedEntry" . | fromJson) -}}
{{ dict "schema" "c8s.allowlist/v1" "workloads" $workloads | toJson }}
{{- end -}}
