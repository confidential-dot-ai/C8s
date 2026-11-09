{{/* Node placement helpers. See ../helpers/nodes/README.md. */}}

{{- define "c8s.criticalPriorityClass" -}}
system-node-critical
{{- end -}}

{{/* The labels this platform puts on a confidential node. Every node agent
     and the router select nodes carrying them. */}}
{{- define "c8s.confidentialNodeLabels" -}}
{{ toYaml .Values.confidentialNodeSelector }}
{{- end -}}
