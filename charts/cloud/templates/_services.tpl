{{/* Services helpers. See ../helpers/services/README.md. */}}

{{/* The attestation-api's Unix socket, which it binds in the node runtime
     directory beside the admission inventory's. */}}
{{- define "c8s.attestationApiSocket" -}}
{{ include "nri-image-policy.runtimeDir" . }}/attestation-api.sock
{{- end -}}

{{- define "c8s.attestationApiURL" -}}
unix://{{ include "c8s.attestationApiSocket" . }}
{{- end -}}

{{/* workloadclaims.InventorySocketGID: the group of the node-local sockets,
     so non-root clients connect by membership. */}}
{{- define "c8s.nodeSocketGID" -}}65532{{- end -}}

{{/* The probe sidecar's listener, which kubelet probes. */}}
{{- define "c8s.attestationApiProbePort" -}}8401{{- end -}}

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
# The node-local socket is the only listener: nothing routable can reach
# /attest.
bind = "{{ include "c8s.attestationApiURL" . }}"
socket_mode = "0660"
socket_group = {{ include "c8s.nodeSocketGID" . }}

[attestation]
enabled = true
{{- end -}}
