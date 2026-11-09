{{/* Services helpers. See ../helpers/services/README.md. */}}

{{/* The attestation-api's Unix socket, which its attest-proxy serves in the
     node runtime directory beside the admission inventory's. */}}
{{- define "c8s.attestationApiSocket" -}}
{{ include "nri-image-policy.runtimeDir" . }}/attestation-api.sock
{{- end -}}

{{- define "c8s.attestationApiURL" -}}
unix://{{ include "c8s.attestationApiSocket" . }}
{{- end -}}

{{- define "c8s.attestationApiPort" -}}8400{{- end -}}

{{/* The attest-proxy's health listener, which kubelet probes. */}}
{{- define "c8s.attestProxyHealthPort" -}}8401{{- end -}}

{{- define "c8s.attestationApiSocketVolume" -}}
- name: attestation-api-socket
  hostPath:
    path: {{ include "nri-image-policy.runtimeDir" . }}
    type: DirectoryOrCreate
{{- end -}}

{{- define "c8s.attestationApiSocketMount" -}}
- name: attestation-api-socket
  mountPath: {{ include "nri-image-policy.runtimeDir" . }}
  readOnly: true
{{- end -}}

{{- define "c8s.attestationApiConfig" -}}
[server]
# Pod loopback only: consumers enter through the attest-proxy sidecar's
# node-local Unix socket; nothing routable can reach /attest.
bind = "127.0.0.1:{{ include "c8s.attestationApiPort" . }}"

[server.tls]
enabled = false

[attestation]
enabled = true

[certs]
cache_max_entries = 1024
{{- end -}}
