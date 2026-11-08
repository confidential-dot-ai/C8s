{{/* The router pod's nginx files and the containers that serve them. */}}

{{/* The router's names and labels. */}}
{{- define "router.fullname" -}}
{{- printf "%s-router" .Release.Name -}}
{{- end }}

{{- define "router.selectorLabels" -}}
app.kubernetes.io/name: router
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "router.labels" -}}
{{ include "router.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/* The node's verified launch staging, and the directories the nginx files
     name: where the worker image installs them
     (nodeservices.RouterTLSSnippetDir) and where its node stages the
     settings they include. */}}
{{- define "c8s.nodeConfigDir" -}}/run/c8s-node{{- end -}}
{{- define "c8s.routerWorkerConfigDir" -}}/usr/lib/c8s/router-nginx{{- end -}}
{{- define "c8s.routerWorkerSettingsDir" -}}{{ include "c8s.nodeConfigDir" . }}/router{{- end -}}

{{/* The files under files/router-nginx as a JSON object, with dir in place of
     both of the worker's directories: one mount holds the files and the
     settings they include. Takes root and dir. */}}
{{- define "c8s.routerNginxFiles" -}}
{{- $dir := .dir -}}
{{- $files := include "c8s.routerNginxWorkerFiles" .root | fromJson -}}
{{- $moved := dict -}}
{{- range $name, $body := $files -}}
{{- $_ := set $moved $name (replace (include "c8s.routerWorkerConfigDir" "") $dir $body | replace (include "c8s.routerWorkerSettingsDir" "") $dir) -}}
{{- end -}}
{{- range $name, $body := $moved -}}
{{- range $worker := list (include "c8s.routerWorkerConfigDir" "") (include "c8s.routerWorkerSettingsDir" "") -}}
{{- if contains $worker $body -}}
{{- fail (printf "router nginx file %s still names the worker's %s after moving its directories to %s" $name $worker $dir) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- $moved | toJson -}}
{{- end -}}

{{/* The worker image's nginx files as a JSON object; fails unless they name
     both of the worker's directories. Takes root. */}}
{{- define "c8s.routerNginxWorkerFiles" -}}
{{- $lib := index .Subcharts "c8s-lib" -}}
{{- $files := dict -}}
{{- range $path, $_ := $lib.Files.Glob "files/router-nginx/*" -}}
{{- $_ := set $files (base $path) ($lib.Files.Get $path) -}}
{{- end -}}
{{- $bodies := values $files | join "\n" -}}
{{- range $worker := list (include "c8s.routerWorkerConfigDir" "") (include "c8s.routerWorkerSettingsDir" "") -}}
{{- if not (contains $worker $bodies) -}}
{{- fail (printf "c8s-lib's router nginx files name no %s, so moving the directory would move nothing" $worker) -}}
{{- end -}}
{{- end -}}
{{- $files | toJson -}}
{{- end -}}

{{/* Ports and paths the files name; c8s.routerContainers and each chart's
     cds-attest argv must match them. */}}
{{- define "router.nginxHTTPSPort" -}}8443{{- end -}}
{{- define "router.attestPort" -}}8800{{- end -}}
{{- define "router.allowlistProxyPort" -}}8801{{- end -}}
{{- define "router.routingPort" -}}8802{{- end -}}
{{- define "router.acmeHTTPPort" -}}8080{{- end -}}
{{- define "router.acmeChallengePort" -}}8402{{- end -}}
{{- define "router.backendTimeout" -}}1h{{- end -}}
{{- define "router.tunnelBodyDir" -}}/var/lib/c8s-tunnel-body{{- end -}}
{{- define "router.acmeCertDir" -}}/etc/c8s-acme-tls{{- end -}}
{{- define "router.acmeKeyDir" -}}/etc/c8s-acme-key{{- end -}}
{{- define "router.discoveryFilePath" -}}/discovery/discovery.json{{- end -}}
{{- define "router.discoveryPath" -}}/v1/discovery{{- end -}}
{{- define "router.cdsCertPath" -}}/.well-known/cds-cert.pem{{- end -}}
{{- define "router.meshCAPath" -}}/.well-known/mesh-ca.pem{{- end -}}

{{/* The paths nginx serves itself, for cds-attest --reserved-paths: no
     manifest route under them is selected (route policy M6). */}}
{{- define "router.reservedPaths" -}}
{{- list
  "/allowlist"
  "/.well-known/c8s/"
  "/.well-known/acme-challenge/"
  (include "router.discoveryPath" .)
  (include "router.cdsCertPath" .)
  (include "router.meshCAPath" .)
  "/readyz"
  "/healthz"
  | join "," -}}
{{- end -}}

{{/*
The router pod's nginx, cds-attest and allowlist-proxy containers. Takes:
  root
  allowlistProxyMounts  the proxy's mounts of the attestation-api it verifies CDS through, as YAML
  allowlistResources    the proxy's container resources
  attestationApiMounts  cds-attest's mounts of the attestation-api it attests through, as YAML
  attestationApiURL     the attestation-api URL a credentials-role container of this pod dials
  certificateMounts     nginx's mounts of the certificates it serves beside the mesh leaf
  cdsAttestArgs         cds-attest's argv after the entrypoint
  cdsAttestMounts       the mounts cdsAttestArgs names beside the mesh leaf and attestation-api
  config                the directory nginx reads the files from
  hostIPEnv             the env a sidecar expands the node's address from, as YAML
  ports                 nginx's ports: name, containerPort, publicPort
  settingsMounts        nginx's mounts of the settings its files include
*/}}
{{- define "c8s.routerContainers" -}}
{{- $root := .root -}}
{{- $v := $root.Values.router -}}
- name: nginx
  image: {{ include "c8s-common.image" (include "c8s.routerNginxPin" $root | fromJson).image }}
  imagePullPolicy: {{ $v.nginx.imagePullPolicy }}
  {{- /* serve.sh stops nginx, its child, when the served certificate is
         withdrawn. The allowlist pins this argv and admits no argument
         beside it. */}}
  command:
    - /bin/sh
    - {{ .config }}/serve.sh
  ports:
    {{- range .ports }}
    - name: {{ .name }}
      containerPort: {{ .containerPort }}
      hostPort: {{ .publicPort }}
      protocol: TCP
    {{- end }}
  securityContext:
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
    runAsNonRoot: true
    runAsUser: {{ include "c8s.routerUID" $root }}
    runAsGroup: {{ include "c8s.routerUID" $root }}
    capabilities:
      drop:
        - ALL
  readinessProbe:
    httpGet:
      path: /healthz
      port: https
      scheme: HTTPS
    initialDelaySeconds: 5
    periodSeconds: 10
  volumeMounts:
    - name: c8s-certs
      mountPath: {{ include "c8s.certDir" $root }}
      readOnly: true
    {{- with .certificateMounts }}
    {{- toYaml . | nindent 4 }}
    {{- end }}
    - name: discovery
      mountPath: /discovery
      readOnly: true
    - name: nginx-config
      mountPath: {{ .config }}
      readOnly: true
    {{- with .settingsMounts }}
    {{- toYaml . | nindent 4 }}
    {{- end }}
    - name: nginx-cache
      mountPath: /var/cache/nginx
    - name: nginx-tmp
      mountPath: /tmp
    - name: nginx-tunnel-body
      mountPath: {{ include "router.tunnelBodyDir" $root }}
  {{- with $v.nginx.resources }}
  resources:
    {{- toYaml . | nindent 4 }}
  {{- end }}
{{- /* It carries every application request nginx's location / sends it
       (route policy A7). */}}
- name: cds-attest
  image: {{ include "c8s.image" $root }}
  imagePullPolicy: {{ default "IfNotPresent" $root.Values.image.pullPolicy }}
  command: {{ include "c8s.entrypoint" (dict "root" $root "valuePath" "image") }}
  args:
    {{- toYaml .cdsAttestArgs | nindent 4 }}
  {{- with .hostIPEnv }}
  env:
    {{- . | nindent 4 }}
  {{- end }}
  volumeMounts:
    - name: c8s-certs
      mountPath: {{ include "c8s.certDir" $root }}
      readOnly: true
    {{- .attestationApiMounts | nindent 4 }}
    {{- with .cdsAttestMounts }}
    {{- toYaml . | nindent 4 }}
    {{- end }}
  securityContext:
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
    runAsNonRoot: true
    {{- /* It dials each route's backend itself: the upstream role's identity
           is the one the node leaves uncaptured into the cluster. */}}
    runAsUser: {{ include "c8s.upstreamUID" $root }}
    runAsGroup: {{ include "c8s.upstreamUID" $root }}
    capabilities:
      drop:
        - ALL
  {{- with $v.attest.resources }}
  resources:
    {{- toYaml . | nindent 4 }}
  {{- end }}
{{- /* It verifies CDS's armTLS evidence before proxying /allowlist, the
       second trust hop behind nginx. */}}
- name: allowlist-proxy
  image: {{ include "c8s.image" $root }}
  imagePullPolicy: {{ default "IfNotPresent" $root.Values.image.pullPolicy }}
  command: {{ include "c8s.entrypoint" (dict "root" $root "valuePath" "image") }}
  args:
    {{- include "router.allowlistProxyArgs" (dict "root" $root "attestationApiURL" .attestationApiURL) | fromJsonArray | toYaml | nindent 4 }}
  {{- with .hostIPEnv }}
  env:
    {{- . | nindent 4 }}
  {{- end }}
  {{- with .allowlistProxyMounts }}
  volumeMounts:
    {{- . | nindent 4 }}
  {{- end }}
  securityContext:
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
    runAsNonRoot: true
    {{- /* It dials CDS, so it holds the credentials role. */}}
    runAsUser: {{ include "c8s.credentialsUID" $root }}
    runAsGroup: {{ include "c8s.credentialsUID" $root }}
    capabilities:
      drop:
        - ALL
  {{- with .allowlistResources }}
  resources:
    {{- toYaml . | nindent 4 }}
  {{- end }}
{{- end -}}

{{/* The proxy holds the credentials role, so the node hands it the one CDS
     its pod may reach and the pins to verify it with, and refuses an argument
     naming either (cmdsutil.ResolveCDSEndpoint, cmdsutil.ResolveCDSPins).
     Takes root and attestationApiURL. */}}
{{- define "router.allowlistProxyArgs" -}}
{{- list "allowlist-proxy" "--host=127.0.0.1" (printf "--port=%s" (include "router.allowlistProxyPort" .root)) (printf "--attestation-api-url=%s" .attestationApiURL) | toJson -}}
{{- end -}}
