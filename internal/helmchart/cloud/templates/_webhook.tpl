{{/* Webhook scope helpers. See ../helpers/webhook/README.md. */}}

{{/* The namespaces the injector leaves alone. The router's is among them
     because the mesh policy designates it for the router role: its pods hold
     platform-role containers the chart renders itself. */}}
{{- define "c8s.webhookExcludedNamespaces" -}}
- key: kubernetes.io/metadata.name
  operator: NotIn
  values:
    - {{ .Release.Namespace }}
    - {{ include "c8s.routerMeshNamespace" . }}
    - kube-system
    - kube-public
    - kube-node-lease
    {{- if not .Values.node.baked }}
    - local-path-storage
    {{- end }}
    {{- range .Values.webhook.extraExcluded }}
    - {{ . }}
    {{- end }}
{{- end }}

{{/* AKS's admissions enforcer honors this opt-out; explicit annotations win. */}}
{{- define "c8s.webhookAnnotations" -}}
{{- $annotations := deepCopy (.Values.webhook.annotations | default dict) -}}
{{- if and (eq (.Values.attestationApi.cvmMode | default "bare-metal") "aks") (not (hasKey $annotations "admissions.enforcer/disabled")) -}}
{{- $_ := set $annotations "admissions.enforcer/disabled" "true" -}}
{{- end -}}
{{- with $annotations }}
annotations:
  {{- toYaml . | nindent 2 }}
{{- end -}}
{{- end -}}
