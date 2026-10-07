{{/* Services helpers. See ../helpers/services/README.md. */}}

{{/* c8s.attestationApiSocketPresent is non-empty when a node-local attestation
API socket exists: either the chart runs the API or the node image bakes it. */}}
{{- define "c8s.attestationApiSocketPresent" -}}
{{- if or .Values.attestationApi.enabled .Values.node.baked -}}true{{- end -}}
{{- end -}}

{{/* Public launch policy only: the token-bearing /run/confos/launch is never
mounted into pods. Directory requires verified staging to have completed. */}}
{{- define "c8s.nodeConfigVolume" -}}
{{- if .Values.node.baked }}
- name: node-config
  hostPath:
    path: /run/c8s-node
    type: Directory
{{- end }}
{{- end -}}

{{- define "c8s.nodeConfigMount" -}}
{{- if .Values.node.baked }}
- name: node-config
  mountPath: /run/c8s-node
  readOnly: true
{{- end }}
{{- end -}}

{{- define "c8s.attestationApiURL" -}}
{{- if include "c8s.attestationApiSocketPresent" . -}}
unix://{{ include "c8s.attestationApiSocket" . }}
{{- else -}}
http://$(HOST_IP):{{ .Values.attestationApi.port }}
{{- end -}}
{{- end -}}

{{- define "c8s.attestationApiSocket" -}}
{{ .Values.nriImagePolicy.hostPaths.runtimeDir }}/attestation-api.sock
{{- end -}}

{{- define "c8s.attestationApiSocketVolume" -}}
{{- if include "c8s.attestationApiSocketPresent" . }}
- name: attestation-api-socket
  hostPath:
    path: {{ .Values.nriImagePolicy.hostPaths.runtimeDir }}
    type: {{ ternary "Directory" "DirectoryOrCreate" .Values.node.baked }}
{{- end }}
{{- end -}}

{{- define "c8s.attestationApiSocketMount" -}}
{{- if include "c8s.attestationApiSocketPresent" . }}
- name: attestation-api-socket
  mountPath: {{ .Values.nriImagePolicy.hostPaths.runtimeDir }}
  readOnly: true
{{- end }}
{{- end -}}

{{- define "c8s.attestationApiHostIPEnv" -}}
{{- if and (not (include "c8s.attestationApiSocketPresent" .)) (eq .Values.attestationApi.cvmMode "bare-metal") -}}
- name: HOST_IP
  valueFrom:
    fieldRef:
      fieldPath: status.hostIP
{{- end -}}
{{- end -}}

{{- define "c8s.nriCDSURL" -}}
{{- if .Values.nriImagePolicy.cds.url -}}
{{ .Values.nriImagePolicy.cds.url }}
{{- else -}}
{{ printf "https://127.0.0.1:%d" (int .Values.cds.service.nodePort) }}
{{- end -}}
{{- end -}}

{{- define "c8s.cdsURL" -}}
https://{{ include "c8s.cdsName" . }}.{{ .Release.Namespace }}.svc:{{ .Values.cds.port }}
{{- end -}}

{{- define "c8s.attestationApiConfig" -}}
{{- $root := .root -}}
[server]
# Pod loopback only: consumers enter through the attest-proxy sidecar's
# node-local Unix socket; nothing routable can reach /attest.
bind = "127.0.0.1:{{ $root.Values.attestationApi.port }}"

[server.tls]
enabled = false

[attestation]
enabled = true
platforms = [{{- range $i, $p := $root.Values.attestationApi.platforms -}}
  {{- if $i }}, {{ end -}}{{- $p | quote -}}
{{- end -}}]

[certs]
cache_max_entries = 1024
{{- end -}}

{{- define "c8s.router.resolver" -}}
{{- if .Values.router.nginx.resolver -}}
{{- .Values.router.nginx.resolver -}}
{{- else if eq .Values.nriImagePolicy.distro "rke2" -}}
rke2-coredns-rke2-coredns.kube-system.svc.cluster.local
{{- else -}}
kube-dns.kube-system.svc.cluster.local
{{- end -}}
{{- end -}}
