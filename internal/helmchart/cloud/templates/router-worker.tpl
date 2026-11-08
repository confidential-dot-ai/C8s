{{/* The measured worker image's front door: the nginx files from its /usr,
     their settings and the CDS pin from the node's verified launch staging
     under /run/c8s-node, and the acme sidecar for the launch file's
     hostnames. */}}

{{- define "router.workerPublicPorts" -}}
{{- list
  (dict "name" "https" "containerPort" (include "router.nginxHTTPSPort" . | int) "publicPort" 443)
  (dict "name" "http" "containerPort" (include "router.acmeHTTPPort" . | int) "publicPort" 80)
  | toJson -}}
{{- end -}}

{{- define "router.acmeReadyPort" -}}8403{{- end -}}

{{- define "router.workerFrontDoor" -}}
{{- $settings := include "c8s.routerWorkerSettingsDir" . -}}
replicas: 1
getCert:
  sanFile: {{ include "c8s.nodeConfigDir" . }}/tls-san
  publicTLSArgs:
    - --discovery-public-tls-mode-file={{ $settings }}/front-door-mode
    - --discovery-public-tls-hostnames-file={{ $settings }}/hostnames
  {{- /* Renew past a stamp taken while only part of the pod runs: clients
         pin the workload stamp. */}}
  {{- with include "c8s.routerEntryName" . }}
  args:
    - --expected-workload={{ . }}
  {{- end }}
  mounts:
    {{- include "router.nodeConfigMount" . | nindent 4 }}
sidecars:
  {{- /* Issues one ACME leaf for the launch file's hostnames, answers HTTP-01
         behind nginx's :80 server, and stands by when it names none. An HTTP
         startup probe holds nginx until the leaf it names exists: the node
         denies every runc exec it was not granted. */}}
  - name: acme
    image: {{ include "c8s.image" . }}
    imagePullPolicy: {{ default "IfNotPresent" .Values.image.pullPolicy }}
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
      {{- /* The key apart from the chain, so a reader of the chain never
             holds the key. */}}
      - name: acme-key
        mountPath: {{ include "router.acmeKeyDir" . }}
      - name: c8s-certs
        mountPath: {{ include "c8s.certDir" . }}
        readOnly: true
      {{- include "router.nodeConfigMount" . | nindent 6 }}
    securityContext:
      {{- include "c8s.getCertSecurityContext" (dict
        "runAsUser" (include "c8s.acmeUID" .)
        "runAsGroup" (include "c8s.acmeUID" .)
      ) | nindent 6 }}
certificateMounts:
  - name: acme-tls
    mountPath: {{ include "router.acmeCertDir" . }}
    readOnly: true
  - name: acme-key
    mountPath: {{ include "router.acmeKeyDir" . }}
    readOnly: true
settingsMounts:
  {{- include "router.nodeConfigMount" . | nindent 2 }}
cdsAttestArgs: {{ include "router.workerCDSAttestArgs" . }}
cdsAttestMounts:
  {{- include "router.nodeConfigMount" . | nindent 2 }}
  - name: acme-tls
    mountPath: {{ include "router.acmeCertDir" . }}
    readOnly: true
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
configVolume:
  hostPath:
    path: {{ include "c8s.routerWorkerConfigDir" . }}
    type: Directory
{{- end -}}

{{- define "router.nodeConfigMount" -}}
- name: node-config
  mountPath: {{ include "c8s.nodeConfigDir" . }}
  readOnly: true
{{- end -}}

{{/* cds-attest takes the front-door mode, the CDS pin and the operator keys
     from the launch staging, naming each so a missing file is fatal. */}}
{{- define "router.workerCDSAttestArgs" -}}
{{- $node := include "c8s.nodeConfigDir" . -}}
{{- concat
  (include "router.cdsAttestListenerArgs" . | fromJsonArray)
  (list
    (printf "--front-door-mode-file=%s/front-door-mode" (include "c8s.routerWorkerSettingsDir" .))
    (printf "--serving-cert-file=%s" (include "c8s.certFile" .))
    (printf "--acme-serving-cert-file=%s/cert.pem" (include "router.acmeCertDir" .)))
  (include "router.measuredPoliciesArgs" . | fromJsonArray)
  (list
    (printf "--image-policy-file=%s/cds.json" $node)
    (printf "--operator-keys-file=%s/operator-pubkey" $node))
  (include "router.cdsAttestRoutingArgs" . | fromJsonArray)
  | toJson -}}
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
