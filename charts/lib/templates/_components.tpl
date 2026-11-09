{{/* files/components.yaml, the component table and the router's nginx pin.
     Every accessor takes the root context, which carries the subchart. */}}
{{- define "c8s.componentsFile" -}}
{{- $lib := index (.Subcharts | default dict) "c8s-lib" -}}
{{- if not $lib -}}
{{- fail "c8s.componentsFile needs the root context of a chart depending on c8s-lib" -}}
{{- end -}}
{{- $lib.Files.Get "files/components.yaml" -}}
{{- end -}}

{{/* The component table as a JSON list. */}}
{{- define "c8s.componentList" -}}
{{- (include "c8s.componentsFile" . | fromYaml).components | toJson -}}
{{- end -}}

{{/* The router's nginx image, entrypoint and imageEnv as a JSON object. */}}
{{- define "c8s.routerNginxPin" -}}
{{- (include "c8s.componentsFile" . | fromYaml).routerNginx | toJson -}}
{{- end -}}
