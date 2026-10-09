{{/* Common helpers. See ../helpers/common/README.md. */}}

{{- define "c8s.fullname" -}}
{{- printf "%s" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "c8s.operatorName" -}}
{{- printf "%s-operator" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "c8s.attestationApiName" -}}
{{- printf "%s-attestation-api" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "c8s.cdsName" -}}
{{- printf "%s-cds" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "c8s.volumedName" -}}
{{- printf "%s-volumed" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "c8s.int" -}}
{{- if and (not (kindIs "int" .)) (not (kindIs "float64" .)) (not (regexMatch "^-?[0-9]+$" (toString .))) -}}
{{- fail (printf "expected an integer, got %q" (toString .)) -}}
{{- end -}}
{{- int64 . -}}
{{- end -}}

{{- define "c8s.positiveInt" -}}
{{- if not (regexMatch `^[1-9][0-9]*$` (toString .value)) -}}
{{- fail (printf "%s must be a positive integer, got: %v" .label .value) -}}
{{- end -}}
{{- toString .value -}}
{{- end -}}

{{- define "c8s.commonLabels" -}}
app.kubernetes.io/name: c8s-operator
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: Helm
{{- end -}}

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
    {{- range .Values.webhook.extraExcluded }}
    - {{ . }}
    {{- end }}
{{- end }}

{{/* The reserved identities and ports of the platform roles. These mirror
     pkg/workloadclaims (MeshUID, CredentialsUID, RouterUID, AcmeUID,
     Mesh*Port), which the injector builds the containers from and the enforcer
     matches on; a chart test pins them to those constants. */}}
{{- define "c8s.meshUID" -}}1337{{- end -}}
{{- define "c8s.credentialsUID" -}}1338{{- end -}}
{{- define "c8s.routerUID" -}}1339{{- end -}}
{{- define "c8s.acmeUID" -}}1340{{- end -}}
{{- define "c8s.meshOutboundPort" -}}15001{{- end -}}
{{- define "c8s.meshInboundPort" -}}15006{{- end -}}
{{- define "c8s.meshHealthPort" -}}15021{{- end -}}

{{/* The credential volume of a member pod: the directory and file names the
     injector fixes (internal/webhook/pod_mutator.go), which the measured base
     pins in the mesh endpoint's argv. A chart-rendered member pod publishes
     and reads the same paths, or its endpoint takes no mesh role. */}}
{{- define "c8s.certDir" -}}/etc/c8s/certs{{- end -}}
{{/* The volume's group, which kubelet adds to every container of the pod, so
     the roles that read a credential can read what the credentials role
     wrote. The injector applies it to a tenant pod (webhook.certVolume). */}}
{{- define "c8s.certFsGroup" -}}{{ include "c8s.int" .Values.webhook.certVolume.fsGroup }}{{- end -}}
{{- define "c8s.certFile" -}}{{ include "c8s.certDir" . }}/tls.crt{{- end -}}
{{- define "c8s.keyFile" -}}{{ include "c8s.certDir" . }}/tls.key{{- end -}}
{{- define "c8s.caFile" -}}{{ include "c8s.certDir" . }}/ca.crt{{- end -}}
