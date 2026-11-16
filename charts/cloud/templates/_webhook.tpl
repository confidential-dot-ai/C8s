{{/* Cloud webhook helpers. See ../helpers/README.md. */}}

{{- define "c8s.cloudAdditionalExcludedNamespaces" -}}
{{- concat .Values.controlPlane.webhook.extraExcluded (.Values.nriImagePolicy.policy.exemptNamespaces | default list) | uniq | toYaml -}}
{{- end -}}
