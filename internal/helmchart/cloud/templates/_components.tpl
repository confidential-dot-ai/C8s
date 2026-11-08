{{/* The component workloads this release runs, as a JSON list of
     [name, pod spec template] for c8s.componentPods. */}}
{{- define "c8s.componentPodTemplates" -}}
{{- $templates := list (list "operator" "c8s.operatorPodSpec") -}}
{{- if .Values.attestationApi.enabled -}}{{- $templates = append $templates (list "attestation-api" "c8s.attestationApiPodSpec") -}}{{- end -}}
{{- if .Values.armtlsMesh.enabled -}}{{- $templates = append $templates (list "armtls-mesh" "armtls-mesh.podSpec") -}}{{- end -}}
{{- if .Values.volumed.enabled -}}
{{- $templates = append $templates (list "volumed" "c8s.volumedPodSpec") -}}
{{- $templates = append $templates (list "volumed-teardown" "c8s.volumedTeardownPodSpec") -}}
{{- end -}}
{{- $templates = append $templates (list "router" "router.podSpec") -}}
{{ $templates | toJson }}
{{- end -}}
