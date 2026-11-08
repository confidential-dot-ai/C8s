{{/* Services helpers. See ../helpers/services/README.md. */}}

{{/* c8s.attestationApiSocketPresent is non-empty when a node-local attestation
API socket exists: either the chart runs the API or the node image bakes it. */}}
{{- define "c8s.attestationApiSocketPresent" -}}
{{- if or .Values.attestationApi.enabled .Values.node.baked -}}true{{- end -}}
{{- end -}}

{{- define "c8s.attestationApiURL" -}}
{{- if include "c8s.attestationApiSocketPresent" . -}}
unix://{{ include "c8s.attestationApiSocket" . }}
{{- else if include "c8s.attestationApiNodeIPFile" . -}}
{{- /* $$ reaches the container as a literal $(NODE_IP), which the binary
       reads from the node-ip file (cmdsutil.ExpandHostIP). */ -}}
http://$$(NODE_IP):{{ .Values.attestationApi.port }}
{{- else -}}
{{- include "c8s.sidecarAttestationApiURL" . -}}
{{- end -}}
{{- end -}}

{{- /* The URL the operator hands the sidecars it injects. Their args are the
       pod's, so the kubelet expands $(HOST_IP) in them from the variable the
       webhook sets. */ -}}
{{- define "c8s.sidecarAttestationApiURL" -}}
{{- if include "c8s.attestationApiSocketPresent" . -}}
unix://{{ include "c8s.attestationApiSocket" . }}
{{- else -}}
{{- /* $$ reaches the container as a literal $(HOST_IP), which the binary
       expands (cmdsutil.ExpandHostIP): the allowlist pins a component's
       arguments exactly, so the kubelet must not put the node's address in
       them. */ -}}
http://$$(HOST_IP):{{ .Values.attestationApi.port }}
{{- end -}}
{{- end -}}

{{- /* "true" when an image policy may deny what the allowlist does not
       admit: the chart's plugin in fail-closed mode, or, with the installer
       off (only renderable on bare-metal), the node image's baked plugin,
       whose mode the chart cannot see. */ -}}
{{- define "c8s.imagePolicyFailClosed" -}}
{{- if or (not .Values.nriImagePolicy.enabled) (eq .Values.nriImagePolicy.policy.mode "fail-closed") -}}true{{- end -}}
{{- end -}}

{{- /* Non-empty when components reach the attestation-api by node address
       and read it from the node-ip file the image policy plugin or the node
       image's nri-node-ip.service writes: bare-metal without a local socket,
       under a fail-closed image policy. The allowlist pins the file's host
       path but not the environment, so HOST_IP would let the pod choose the
       verifier. */ -}}
{{- define "c8s.attestationApiNodeIPFile" -}}
{{- if and (not (include "c8s.attestationApiSocketPresent" .)) (eq .Values.attestationApi.cvmMode "bare-metal") (include "c8s.imagePolicyFailClosed" .) -}}true{{- end -}}
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
{{- else if include "c8s.attestationApiNodeIPFile" . }}
- name: node-ip
  hostPath:
    path: {{ .Values.nriImagePolicy.hostPaths.runtimeDir }}/node-ip
    type: File
{{- end }}
{{- end -}}

{{- /* Mounts the socket directory, or the node-ip file at cmdsutil.NodeIPPath
       where the attestation-api URL names $(NODE_IP). */ -}}
{{- define "c8s.attestationApiSocketMount" -}}
{{- if include "c8s.attestationApiSocketPresent" . }}
- name: attestation-api-socket
  mountPath: {{ .Values.nriImagePolicy.hostPaths.runtimeDir }}
  readOnly: true
{{- else if include "c8s.attestationApiNodeIPFile" . }}
- name: node-ip
  mountPath: /run/c8s/node-ip
  readOnly: true
{{- end }}
{{- end -}}

{{- define "c8s.attestationApiHostIPEnv" -}}
{{- if and (not (include "c8s.attestationApiSocketPresent" .)) (eq .Values.attestationApi.cvmMode "bare-metal") (not (include "c8s.attestationApiNodeIPFile" .)) -}}
- name: HOST_IP
  valueFrom:
    fieldRef:
      fieldPath: status.hostIP
{{- end -}}
{{- end -}}

{{/* c8s.cdsFromValues is non-empty where this release's values name the CDS
     its clients trust — cds.address and cds.measurementsConfig — which is
     every install but a baked node, whose signed launch file carries both. */}}
{{- define "c8s.cdsFromValues" -}}
{{- if not .Values.node.baked -}}true{{- end -}}
{{- end -}}

{{/* c8s.installerCopiesCDSAddress is non-empty where the installer that
     copies the CDS endpoint to its node renders: it is the one reader of the
     cds-address key, and a plugin from a measured image takes the endpoint
     from its own launch staging. */}}
{{- define "c8s.installerCopiesCDSAddress" -}}
{{- if and (include "c8s.cdsFromValues" .) .Values.nriImagePolicy.enabled -}}true{{- end -}}
{{- end -}}

{{/* The fixed namespace whose pods serve the router's own ports, as the
     enforcer compiles it (pkg/workloadclaims.RouterNamespace). Not the release
     namespace, whose pods the mesh policy exempts. */}}
{{- define "c8s.routerMeshNamespace" -}}
c8s-router
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
platforms = ["snp", "tdx", "az-snp", "az-tdx", "gcp-snp", "gcp-tdx"]

[certs]
cache_max_entries = 1024
{{- end -}}
