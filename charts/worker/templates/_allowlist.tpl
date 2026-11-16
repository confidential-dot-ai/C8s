{{/* The component workloads this chart runs, as a JSON list of
     [name, pod spec template] for c8s.componentPods: the router alone. */}}
{{- define "worker.componentPodTemplates" -}}
{{ list (list "router" "router.podSpec") | toJson }}
{{- end -}}

{{/* The seed a worker cluster's CDS serves: the component shapes of the
     router and of the sidecars the webhook injects, and the router entry. */}}
{{- define "worker.allowlistSeedJSON" -}}
{{- $shapes := include "c8s.componentShapes" (dict "root" . "templates" (include "worker.componentPodTemplates" .)) -}}
{{- $workloads := include "c8s.shapeWorkloads" $shapes | fromJson -}}
{{- $_ := set $workloads (include "c8s.routerWorkloadName" .) (include "c8s.routerEntry" . | fromJson) -}}
{{ dict "schema" "c8s.allowlist/v1" "workloads" $workloads | toJson }}
{{- end -}}
