{{/* The measured worker image's front door: nginx files from its /usr, their
     settings and the CDS pin from the node's verified launch staging under
     /run/c8s-node, and the acme sidecar for the launch file's hostnames. */}}

{{- define "router.configDir" -}}{{ include "c8s.routerWorkerConfigDir" . }}{{- end -}}

{{/* nginx's ports: name, containerPort, and publicPort, the host port the
     node publishes it on and the Service port that targets it. */}}
{{- define "router.publicPorts" -}}
{{- list
  (dict "name" "https" "containerPort" (include "router.nginxHTTPSPort" . | int) "publicPort" 443)
  (dict "name" "http" "containerPort" (include "router.acmeHTTPPort" . | int) "publicPort" 80)
  | toJson -}}
{{- end -}}

{{- define "router.acmeReadyPort" -}}8403{{- end -}}

{{- define "router.podSpec" -}}
{{- $inventoryURL := include "worker.attestationApiURL" (dict "dir" (include "worker.inventoryDir" .)) -}}
# Keeps the env names fixed for the allowlist's env match (c8s.componentEnv).
enableServiceLinks: false
{{- /* Every container holds a platform role the measured base grants it and
       runs as that role's reserved identity (c8s-lib's _identities.tpl). */}}
initContainers:
  {{- include "c8s.meshEndpointContainer" . | nindent 2 }}
  {{- include "c8s.getCertContainers" (dict
    "root" .
    "attestationApiURL" $inventoryURL
    "extraArgs" (include "router.getCertArgs" . | fromJsonArray)
    "extraMounts" (include "router.getCertMounts" .)
    "renewInterval" "1h"
    "sanFile" (printf "%s/tls-san" (include "c8s.nodeConfigDir" .))
  ) | nindent 2 }}
  {{- include "router.acmeContainer" . | nindent 2 }}
containers:
  {{- include "c8s.routerContainers" (dict
    "root" .
    "allowlistProxyMounts" (include "router.inventoryMount" .)
    "attestationApiMounts" (include "router.attestationApiMount" .)
    "attestationApiURL" $inventoryURL
    "certificateMounts" (include "router.acmeCertificateMounts" . | fromYamlArray)
    "cdsAttestArgs" (include "router.cdsAttestArgs" . | fromJsonArray)
    "cdsAttestMounts" (include "router.cdsAttestMounts" . | fromYamlArray)
    "config" (include "router.configDir" .)
    "ports" (include "router.publicPorts" . | fromJsonArray)
    "settingsMounts" (include "router.nodeConfigMount" . | fromYamlArray)
  ) | nindent 2 }}
volumes:
  {{- /* Public launch policy only; Directory requires verified staging to
         have completed. */}}
  - name: node-config
    hostPath:
      path: {{ include "c8s.nodeConfigDir" . }}
      type: Directory
  - name: c8s-certs
    emptyDir:
      medium: Memory
      sizeLimit: 1Mi
  {{- /* Memory-medium and lost with the pod, so the sidecar re-issues. */}}
  - name: acme-tls
    emptyDir:
      medium: Memory
      sizeLimit: 1Mi
  - name: acme-key
    emptyDir:
      medium: Memory
      sizeLimit: 1Mi
  - name: discovery
    emptyDir:
      medium: Memory
      sizeLimit: 1Mi
  - name: nginx-cache
    emptyDir:
      medium: Memory
      sizeLimit: 16Mi
  - name: nginx-tmp
    emptyDir:
      medium: Memory
      sizeLimit: 16Mi
  - name: nginx-tunnel-body
    emptyDir:
      medium: Memory
      sizeLimit: 8Gi
  - name: nginx-config
    hostPath:
      path: {{ include "router.configDir" . }}
      type: Directory
  {{- /* The inventory and the attestation-api serve their sockets in one
         host directory, which get-cert and the allowlist proxy read at the
         path they compile and cds-attest at the node's own. */}}
  - name: workload-claims
    hostPath:
      path: {{ include "worker.runtimeDir" . }}
      type: Directory
  - name: attestation-api-socket
    hostPath:
      path: {{ include "worker.runtimeDir" . }}
      type: Directory
securityContext:
  runAsNonRoot: true
  fsGroup: {{ include "c8s.certFsGroup" (include "worker.inventorySocketGID" .) }}
  supplementalGroups: [{{ include "worker.inventorySocketGID" . }}]
  seccompProfile:
    type: RuntimeDefault
{{- end -}}

{{- define "router.inventoryMount" -}}
- name: workload-claims
  mountPath: {{ include "worker.inventoryDir" . }}
  readOnly: true
{{- end -}}

{{- define "router.attestationApiMount" -}}
- name: attestation-api-socket
  mountPath: {{ include "worker.runtimeDir" . }}
  readOnly: true
{{- end -}}

{{- define "router.nodeConfigMount" -}}
- name: node-config
  mountPath: {{ include "c8s.nodeConfigDir" . }}
  readOnly: true
{{- end -}}

{{- define "router.acmeCertificateMounts" -}}
- name: acme-tls
  mountPath: {{ include "router.acmeCertDir" . }}
  readOnly: true
- name: acme-key
  mountPath: {{ include "router.acmeKeyDir" . }}
  readOnly: true
{{- end -}}

{{- define "router.getCertMounts" -}}
- name: discovery
  mountPath: /discovery
{{ include "router.nodeConfigMount" . }}
{{ include "router.inventoryMount" . }}
{{- end -}}

{{/* Discovery for the front door's public TLS, and a renewal pinned to the
     router entry: clients pin the workload stamp. */}}
{{- define "router.getCertArgs" -}}
{{- $settings := include "c8s.routerWorkerSettingsDir" . -}}
{{- list
  (printf "--discovery-out=%s" (include "router.discoveryFilePath" .))
  (printf "--discovery-cds-cert-url=%s" (include "router.cdsCertPath" .))
  (printf "--discovery-public-tls-mode-file=%s/front-door-mode" $settings)
  (printf "--discovery-public-tls-hostnames-file=%s/hostnames" $settings)
  (printf "--discovery-mesh-ca-url=%s" (include "router.meshCAPath" .))
  "--ca-watch-interval=1m"
  (printf "--expected-workload=%s" (include "c8s.routerWorkloadName" .))
  | toJson -}}
{{- end -}}

{{/* cds-attest takes the front-door mode, the CDS pin and the operator keys
     from the launch staging, naming each so a missing file is fatal. */}}
{{- define "router.cdsAttestArgs" -}}
{{- $node := include "c8s.nodeConfigDir" . -}}
{{- $runtimeDir := include "worker.runtimeDir" . -}}
{{- list
  "cds-attest"
  "--host=127.0.0.1"
  (printf "--port=%s" (include "router.attestPort" .))
  (printf "--platform=%s" .Values.router.attest.platform)
  (printf "--generation=%s" .Values.router.attest.generation)
  (printf "--attestation-api-url=%s" (include "worker.attestationApiURL" (dict "dir" $runtimeDir)))
  (printf "--front-door-mode-file=%s/front-door-mode" (include "c8s.routerWorkerSettingsDir" .))
  (printf "--serving-cert-file=%s" (include "c8s.certFile" .))
  (printf "--acme-serving-cert-file=%s/cert.pem" (include "router.acmeCertDir" .))
  (printf "--measured-policies-file=%s/measured-policies" $runtimeDir)
  (printf "--image-policy-file=%s/cds.json" $node)
  (printf "--operator-keys-file=%s/operator-pubkey" $node)
  "--routes-poll-interval=30s"
  "--routing-host=127.0.0.1"
  (printf "--routing-port=%s" (include "router.routingPort" .))
  (printf "--backend-timeout=%s" (include "router.backendTimeout" .))
  (printf "--reserved-paths=%s" (include "router.reservedPaths" .))
  "--publish-routes"
  | toJson -}}
{{- end -}}

{{- define "router.cdsAttestMounts" -}}
{{ include "router.nodeConfigMount" . }}
- name: acme-tls
  mountPath: {{ include "router.acmeCertDir" . }}
  readOnly: true
{{- end -}}

{{/* Issues one ACME leaf for the launch file's hostnames, answers HTTP-01
     behind nginx's :80 server, and stands by when it names none. An HTTP
     startup probe holds nginx until the leaf exists: the node denies every
     runc exec it was not granted. */}}
{{- define "router.acmeContainer" -}}
- name: acme
  image: {{ include "c8s.image" . }}
  imagePullPolicy: {{ .Values.image.pullPolicy }}
  restartPolicy: Always
  command: {{ include "c8s.entrypoint" (dict "root" . "valuePath" "image") }}
  args: {{ include "router.acmeArgs" . }}
  startupProbe:
    httpGet:
      path: /readyz
      port: acme-ready
    periodSeconds: 1
    failureThreshold: 60
  ports:
    - name: acme-ready
      containerPort: {{ include "router.acmeReadyPort" . }}
  volumeMounts:
    - name: acme-tls
      mountPath: {{ include "router.acmeCertDir" . }}
    {{- /* The key apart from the chain, so a reader of the chain never holds
           the key. */}}
    - name: acme-key
      mountPath: {{ include "router.acmeKeyDir" . }}
    - name: c8s-certs
      mountPath: {{ include "c8s.certDir" . }}
      readOnly: true
    {{- include "router.nodeConfigMount" . | nindent 4 }}
  securityContext:
    {{- include "c8s.getCertSecurityContext" (dict
      "runAsUser" (include "c8s.acmeUID" .)
      "runAsGroup" (include "c8s.acmeUID" .)
    ) | nindent 4 }}
{{- end -}}

{{/* With no hostnames in the launch file, the sidecar stands by until the
     mesh leaf exists. */}}
{{- define "router.acmeArgs" -}}
{{- $dir := include "c8s.routerWorkerSettingsDir" . -}}
{{- list
  "acme"
  (printf "--domains-file=%s/hostnames" $dir)
  (printf "--acme-email-file=%s/acme-email" $dir)
  (printf "--acme-directory-url-file=%s/acme-directory-url" $dir)
  (printf "--standby-cert-dir=%s" (include "c8s.certDir" .))
  (printf "--challenge-port=%s" (include "router.acmeChallengePort" .))
  (printf "--http-port=%s" (include "router.acmeHTTPPort" .))
  (printf "--ready-port=%s" (include "router.acmeReadyPort" .))
  | toJson -}}
{{- end -}}
