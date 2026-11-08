{{/* Webhook helpers. See ../helpers/README.md. */}}

{{/* The namespaces both webhooks leave alone. The router's is among them
     because the mesh policy designates it for the router role: its pods hold
     platform-role containers the chart renders itself. */}}
{{- define "c8s.webhookExcludedNamespacesMatchExpression" -}}
- key: kubernetes.io/metadata.name
  operator: NotIn
  values:
    - {{ .Release.Namespace }}
    - {{ include "c8s.routerMeshNamespace" . }}
    - kube-system
    - kube-public
    - kube-node-lease
    {{- range .Values.webhook.extraExcluded }}
    - {{ . }}
    {{- end }}
{{- end }}

{{- define "c8s.webhookAnnotationsBlock" -}}
{{- with .Values.webhook.annotations }}
annotations:
  {{- toYaml . | nindent 2 }}
{{- end -}}
{{- end -}}

{{/* Takes root and path. */}}
{{- define "c8s.webhookClientConfig" -}}
clientConfig:
  service:
    namespace: {{ .root.Release.Namespace }}
    name: {{ include "c8s.operatorName" .root }}
    path: {{ .path }}
    port: {{ include "c8s.webhookServicePort" . }}
{{- end -}}
