{{/* Node placement helpers. See ../helpers/nodes/README.md. */}}

{{/* The labels this platform puts on a confidential node. Every node agent
     and the router select nodes carrying them. */}}
{{- define "c8s.confidentialNodeLabels" -}}
{{ toYaml .Values.confidentialNodeSelector }}
{{- end -}}
