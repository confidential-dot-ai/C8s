{{/* The Pod CVM provider's grants. See ../helpers/common/README.md. */}}

{{/* Takes a dict with root (the chart context) and subject (the operator's
     RBAC subject). Secrets stay in the release namespace. */}}
{{- define "c8s.podCVMProviderGrants" -}}
{{- $root := .root -}}
{{- $name := printf "%s-pod-cvm" (include "c8s.operatorName" $root) -}}
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: {{ $name }}
  labels:
{{ include "c8s.commonLabels" $root | indent 4 }}
rules:
  - apiGroups: [""]
    resources: [pods]
    verbs: [get, list, watch, update, patch]
  - apiGroups: [""]
    resources: [pods/status]
    verbs: [get, update, patch]
  - apiGroups: [""]
    resources: [nodes, nodes/status]
    verbs: [get, list, watch, create, update, patch]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: {{ $name }}
  labels:
{{ include "c8s.commonLabels" $root | indent 4 }}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: {{ $name }}
subjects:
  - {{- toYaml .subject | nindent 4 }}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ $name }}
  namespace: {{ $root.Release.Namespace }}
  labels:
{{ include "c8s.commonLabels" $root | indent 4 }}
rules:
  - apiGroups: [""]
    resources: [secrets]
    verbs: [get, list, watch, create, update, patch, delete]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{ $name }}
  namespace: {{ $root.Release.Namespace }}
  labels:
{{ include "c8s.commonLabels" $root | indent 4 }}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: {{ $name }}
subjects:
  - {{- toYaml .subject | nindent 4 }}
{{- end -}}
