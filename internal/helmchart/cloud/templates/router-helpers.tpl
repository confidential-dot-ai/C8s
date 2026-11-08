{{/* The cloud front door: c8s-lib's nginx files from one ConfigMap mounted at
     router.configDir, the CDS pin and operator keys from values. */}}

{{/* The single identity baked into the CDS-issued mesh cert (get-cert), which
     the CDS's own leaf DNS rules must admit: the first router.san entry, or
     the chart-managed Service DNS name. */}}
{{- define "router.san" -}}
{{- if .Values.router.san -}}
{{- first .Values.router.san -}}
{{- else -}}
{{- printf "%s.%s.svc" (include "router.fullname" .) (include "c8s.routerMeshNamespace" .) -}}
{{- end -}}
{{- end -}}

{{/* The directory nginx reads the c8s.routerNginxFiles from. */}}
{{- define "router.configDir" -}}/mnt/c8s-data/nginx{{- end -}}

{{/* The files the cloud's nginx ConfigMap holds: c8s-lib's, read from one
     mount, with the settings a worker's node stages from its launch file
     beside them, less front-door-mode (cds-attest takes the mode as pinned
     argv). */}}
{{- define "router.cloudNginxFiles" -}}
{{- $dir := include "router.configDir" . -}}
{{- $files := include "c8s.routerNginxFiles" (dict "root" . "dir" $dir) | fromJson -}}
{{- $_ := set $files "request-body.conf" "client_max_body_size 1048576;\n" -}}
{{- $_ := set $files "tls.conf" (printf "include %s/tls-cds.conf;\n" $dir) -}}
{{- $files | toJson -}}
{{- end -}}

{{/* nginx's ports: name, containerPort, and publicPort, the host port the
     node publishes it on and the Service port that targets it. */}}
{{- define "router.publicPorts" -}}
{{- list (dict "name" "https" "containerPort" (include "router.nginxHTTPSPort" . | int) "publicPort" 443) | toJson -}}
{{- end -}}

{{/* The front door's mounts of the CDS pin and, where set, the operator
     keys; cds-attest reads both. */}}
{{- define "router.cdsAttestMounts" -}}
- name: measurements-config
  mountPath: /mnt/c8s-data/measurements
  readOnly: true
{{- if .Values.cds.operatorKeys }}
- name: operator-keys
  mountPath: /mnt/c8s-data/operator-keys
  readOnly: true
{{- end }}
{{- end -}}

{{/* cds-attest pins the front-door mode and reads the CDS pin and operator
     keys from values. Loopback only: nginx proxies /readyz, the attest routes
     and /tunnel to it. */}}
{{- define "router.cdsAttestArgs" -}}
{{- $args := list
  "cds-attest"
  "--host=127.0.0.1"
  (printf "--port=%s" (include "router.attestPort" .))
  (printf "--platform=%s" .Values.router.attest.platform)
  (printf "--generation=%s" .Values.router.attest.generation)
  (printf "--attestation-api-url=%s" (include "c8s.attestationApiURL" .))
  "--front-door-mode=cds"
  (printf "--serving-cert-file=%s" (include "c8s.certFile" .))
  (printf "--measured-policies-file=%s/measured-policies" (include "nri-image-policy.runtimeDir" .))
  "--image-policy-file=/mnt/c8s-data/measurements/cds.json" -}}
{{- if .Values.cds.operatorKeys -}}
{{- $args = append $args "--operator-keys-file=/mnt/c8s-data/operator-keys/keys.pem" -}}
{{- end -}}
{{- $args = concat $args (list
  (printf "--routes-poll-interval=%s" .Values.router.routing.pollInterval)
  "--routing-host=127.0.0.1"
  (printf "--routing-port=%s" (include "router.routingPort" .))
  (printf "--backend-timeout=%s" (include "router.backendTimeout" .))
  (printf "--reserved-paths=%s" (include "router.reservedPaths" .))) -}}
{{- if .Values.router.routePublication.enabled -}}
{{- $args = append $args "--publish-routes" -}}
{{- end -}}
{{- $args | toJson -}}
{{- end -}}

{{/* get-cert redeems a sandbox token from the node inventory at its compiled
     socket path (workloadclaims.SidecarSocketDir), where the pod mounts the
     inventory's directory. That directory's attestation-api socket is the
     only verifier the credentials role accepts (cmdsutil.RequireNodeVerifier). */}}
{{- define "router.inventoryDir" -}}/run/c8s/workload-claims{{- end -}}

{{- define "router.inventoryMount" -}}
- name: workload-claims
  mountPath: {{ include "router.inventoryDir" . }}
  readOnly: true
{{- end -}}

{{/* The attestation-api socket at the inventory path get-cert and the
     allowlist proxy compile; cds-attest takes the node's own path, beside the
     measured-policy journal it reads. */}}
{{- define "router.attestationApiURL" -}}
unix://{{ include "router.inventoryDir" . }}/attestation-api.sock
{{- end -}}

{{- define "router.getCertArgs" -}}
{{- list
  (printf "--discovery-out=%s" (include "router.discoveryFilePath" .))
  (printf "--discovery-cds-cert-url=%s" (include "router.cdsCertPath" .))
  "--discovery-public-tls-mode=cds"
  (printf "--discovery-mesh-ca-url=%s" (include "router.meshCAPath" .))
  "--ca-watch-interval=1m"
  | toJson -}}
{{- end -}}

{{- define "router.getCertMounts" -}}
- name: discovery
  mountPath: /discovery
{{ include "router.inventoryMount" . }}
{{- end -}}
