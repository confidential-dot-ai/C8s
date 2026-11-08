{{/*
Expand the name of the chart.
*/}}
{{- define "router.name" -}}
{{- default "router" .Values.router.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "router.fullname" -}}
{{- printf "%s-router" .Release.Name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
The single identity baked into the CDS-issued mesh cert (get-cert), which the
CDS's own leaf DNS rules must admit: the first entry of the router.san list,
or the chart-managed Service DNS name (<release>-router.c8s-router.svc) where
that list is empty. Every entry is validated: `c8s install --upstream` routes
them all.
*/}}
{{- define "router.san" -}}
{{- $san := .Values.router.san -}}
{{- if not (kindIs "slice" $san) -}}
{{- fail (printf "router.san must be a list of hostnames, got %s: %v" (kindOf $san) $san) -}}
{{- end -}}
{{- range $s := $san -}}{{- include "router.validateSan" $s -}}{{- end -}}
{{- if $san -}}
{{- first $san -}}
{{- else -}}
{{- printf "%s.%s.svc" (include "router.fullname" .) (include "c8s.routerMeshNamespace" .) -}}
{{- end -}}
{{- end -}}

{{/*
Common labels.
*/}}
{{- define "router.labels" -}}
helm.sh/chart: router-0.5.0
{{ include "router.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Validate that a san entry is a DNS hostname or a wildcard (e.g. *.example.com).
*/}}
{{- define "router.validateSan" -}}
{{- if regexMatch `[^a-zA-Z0-9.*-]` . -}}
{{- fail (printf "san contains invalid characters: %s - only alphanumeric, dots, hyphens, and wildcards are allowed" .) -}}
{{- end -}}
{{- end -}}

{{/*
Selector labels.
*/}}
{{- define "router.selectorLabels" -}}
app.kubernetes.io/name: {{ include "router.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/* A baked node renders the measured worker image's front door
     (router-worker.tpl), every other release the cloud's. */}}

{{/* The directory nginx reads the c8s.routerNginxFiles from. */}}
{{- define "router.configDir" -}}
{{- if .Values.node.baked -}}{{ include "c8s.routerWorkerConfigDir" . }}{{- else -}}{{ include "router.cloudConfigDir" . }}{{- end -}}
{{- end -}}

{{/* nginx's ports: name, containerPort, and publicPort, the node and Service
     port each is published on. */}}
{{- define "router.publicPorts" -}}
{{- if .Values.node.baked -}}{{ include "router.workerPublicPorts" . }}{{- else -}}{{ include "router.cloudPublicPorts" . }}{{- end -}}
{{- end -}}

{{/* The router pod's parts that differ between front doors, as YAML. */}}
{{- define "router.frontDoor" -}}
{{- if .Values.node.baked -}}{{ include "router.workerFrontDoor" . }}{{- else -}}{{ include "router.cloudFrontDoor" . }}{{- end -}}
{{- end -}}

{{- define "router.cloudConfigDir" -}}/mnt/c8s-data/nginx{{- end -}}

{{/* The files the cloud's nginx ConfigMap holds: c8s-lib's, read from one
     mount, with the settings a worker's node stages from its launch file
     beside them, less front-door-mode (cds-attest takes the mode as pinned
     argv). */}}
{{- define "router.cloudNginxFiles" -}}
{{- $dir := include "router.cloudConfigDir" . -}}
{{- $maxRequestBodyBytes := include "c8s.int" .Values.router.routing.maxRequestBodyBytes | int64 -}}
{{- if lt $maxRequestBodyBytes 1 -}}
{{- fail (printf "router.routing.maxRequestBodyBytes must be a positive number of bytes, got: %d" $maxRequestBodyBytes) -}}
{{- end -}}
{{- $files := include "c8s.routerNginxFiles" (dict "root" . "dir" $dir) | fromJson -}}
{{- $_ := set $files "request-body.conf" (printf "client_max_body_size %d;\n" $maxRequestBodyBytes) -}}
{{- $_ := set $files "tls.conf" (printf "include %s/tls-cds.conf;\n" $dir) -}}
{{- $files | toJson -}}
{{- end -}}

{{- define "router.cloudPublicPorts" -}}
{{- list (dict "name" "https" "containerPort" (include "router.nginxHTTPSPort" . | int) "publicPort" 443) | toJson -}}
{{- end -}}

{{/* The files and their settings come from one ConfigMap; the CDS pin and
     operator keys from values. */}}
{{- define "router.cloudFrontDoor" -}}
{{- $operatorKeys := .Values.cds.operatorKeys -}}
replicas: {{ .Values.router.nginx.replicas }}
podAnnotations:
  checksum/measurements-config: {{ .Values.cds.measurementsConfig | sha256sum }}
  {{- with $operatorKeys }}
  checksum/operator-keys: {{ . | sha256sum }}
  {{- end }}
getCert:
  san: {{ include "router.san" . | quote }}
  publicTLSArgs:
    - --discovery-public-tls-mode=cds
cdsAttestArgs: {{ include "router.cloudCDSAttestArgs" . }}
cdsAttestMounts:
  - name: measurements-config
    mountPath: /mnt/c8s-data/measurements
    readOnly: true
  {{- if $operatorKeys }}
  - name: operator-keys
    mountPath: /mnt/c8s-data/operator-keys
    readOnly: true
  {{- end }}
volumes:
  - name: c8s-certs
    emptyDir:
      medium: Memory
      sizeLimit: 1Mi
  - name: measurements-config
    projected:
      sources:
        - configMap:
            name: {{ include "c8s.fullname" . }}-measurements
  {{- if $operatorKeys }}
  - name: operator-keys
    projected:
      sources:
        - configMap:
            name: {{ include "c8s.fullname" . }}-operator-keys
  {{- end }}
configVolume:
  projected:
    sources:
      - configMap:
          name: {{ include "router.fullname" . }}-nginx
{{- end -}}

{{/* cds-attest pins the front-door mode and reads the CDS pin and operator
     keys from values. */}}
{{- define "router.cloudCDSAttestArgs" -}}
{{- $operatorKeys := list -}}
{{- if .Values.cds.operatorKeys -}}
{{- $operatorKeys = list "--operator-keys-file=/mnt/c8s-data/operator-keys/keys.pem" -}}
{{- end -}}
{{- concat
  (include "router.cdsAttestListenerArgs" . | fromJsonArray)
  (list
    "--front-door-mode=cds"
    (printf "--serving-cert-file=%s" (include "c8s.certFile" .)))
  (include "router.measuredPoliciesArgs" . | fromJsonArray)
  (list "--image-policy-file=/mnt/c8s-data/measurements/cds.json")
  $operatorKeys
  (include "router.cdsAttestRoutingArgs" . | fromJsonArray)
  | toJson -}}
{{- end -}}

{{/*
Bytes in a Kubernetes quantity written as an integer with an optional k, M,
G, T, Ki, Mi, Gi or Ti suffix; "" for any other form.
*/}}
{{- define "router.quantityBytes" -}}
{{- $q := toString . -}}
{{- $digits := regexFind `^[0-9]+` $q -}}
{{- $units := dict "" 1 "k" 1000 "M" 1000000 "G" 1000000000 "T" 1000000000000 "Ki" 1024 "Mi" 1048576 "Gi" 1073741824 "Ti" 1099511627776 -}}
{{- $suffix := trimPrefix $digits $q -}}
{{- if and $digits (hasKey $units $suffix) -}}{{ mul ($digits | int64) (get $units $suffix) }}{{- end -}}
{{- end -}}

{{/*
The front door's discovery and get-cert args, as a JSON list for
c8s.getCertContainers' extraArgs. Takes root and getCert, whose publicTLSArgs
report the front door's public TLS mode.
*/}}
{{- define "router.getCertCommonArgs" -}}
{{- $root := .root -}}
{{- $args := list (printf "--discovery-out=%s" (include "router.discoveryFilePath" $root)) (printf "--discovery-cds-cert-url=%s" (include "router.cdsCertPath" $root)) -}}
{{- $args = concat $args .getCert.publicTLSArgs (list (printf "--discovery-mesh-ca-url=%s" (include "router.meshCAPath" $root))) -}}
{{- with $root.Values.router.certProvisioning.caWatchInterval -}}
{{- $args = append $args (printf "--ca-watch-interval=%v" .) -}}
{{- end -}}
{{- if $root.Values.router.certProvisioning.verbose -}}
{{- $args = append $args "--verbose" -}}
{{- end -}}
{{- $args | toJson -}}
{{- end -}}

{{/* cds-attest's listener and the TEE it attests. Loopback only: nginx
     proxies /readyz, the attest routes and /tunnel to it. */}}
{{- define "router.cdsAttestListenerArgs" -}}
{{- $v := .Values.router.attest -}}
{{- list
  "cds-attest"
  "--host=127.0.0.1"
  (printf "--port=%s" (include "router.attestPort" .))
  (printf "--platform=%v" $v.platform)
  (printf "--generation=%v" $v.generation)
  (printf "--attestation-api-url=%s" (default (include "c8s.attestationApiURL" .) $v.attestationApiURL))
  | toJson -}}
{{- end -}}

{{/* The NRI plugin's measured-policy journal, under the attestation-api
     socket mount; an absent journal omits the list. */}}
{{- define "router.measuredPoliciesArgs" -}}
{{- $args := list -}}
{{- if include "c8s.attestationApiSocketPresent" . -}}
{{- $args = append $args (printf "--measured-policies-file=%s/measured-policies" .Values.nriImagePolicy.hostPaths.runtimeDir) -}}
{{- end -}}
{{- $args | toJson -}}
{{- end -}}

{{/* Routing by the operator-signed manifest polled from the verified CDS:
     application requests from nginx on the loopback routing listener, and
     requests decrypted from the tunnel. */}}
{{- define "router.cdsAttestRoutingArgs" -}}
{{- $routing := .Values.router.routing -}}
{{- $args := list
  (printf "--routes-poll-interval=%s" (toString $routing.pollInterval))
  "--routing-host=127.0.0.1"
  (printf "--routing-port=%s" (include "router.routingPort" .))
  (printf "--backend-timeout=%s" (include "router.backendTimeout" .)) -}}
{{- with $routing.tunnelBudget -}}
{{- $args = append $args (printf "--tunnel-budget=%s" .) -}}
{{- end -}}
{{- $args = append $args (printf "--reserved-paths=%s" (include "router.reservedPaths" .)) -}}
{{- /* Serves the applied signed manifest at /.well-known/c8s/routes. */ -}}
{{- if dig "routePublication" "enabled" false .Values.router -}}
{{- $args = append $args "--publish-routes" -}}
{{- end -}}
{{- $args | toJson -}}
{{- end -}}

{{/*
"true" when the router pod must mount the node inventory's socket directory:
the node runs an admission inventory for get-cert to redeem a sandbox token at.
The pod's own mesh endpoint adopts only a leaf that names a workload instance
(internal/cmds/armtlsmesh), so a router whose get-cert redeems no token has no
endpoint and carries no traffic.

The condition mirrors the operator's own inventory condition
(operator.yaml): the directory exists only where an installer put it, and a
`type: Directory` hostPath naming a path nothing created wedges the pod in
ContainerCreating. validations.yaml (kind=require_host_image_policy) makes that
condition true in every renderable shape today; the condition is spelled out
anyway so the two consumers of the socket stay on one rule.
*/}}
{{/*
router.credentialsVerifierURL — the attestation-api a credentials-role
container of this pod verifies CDS through. A node running the admission
inventory this pod mounts at the compiled path serves its own attestation-api
in that directory, and that socket is the only verifier its clients accept
(cmdsutil.RequireNodeVerifier); elsewhere the cluster's own endpoint stands.
*/}}
{{- define "router.credentialsVerifierURL" -}}
{{- if eq (include "router.mountInventorySocket" .) "true" -}}
unix:///run/c8s/workload-claims/attestation-api.sock
{{- else -}}
{{ include "c8s.attestationApiURL" . }}
{{- end -}}
{{- end -}}

{{- define "router.mountInventorySocket" -}}
{{- if or .Values.nriImagePolicy.enabled (eq .Values.attestationApi.cvmMode "bare-metal") -}}
true
{{- end -}}
{{- end -}}

{{/*
c8s-cert native sidecar (restartPolicy: Always): obtains the leaf on startup
and renews it on a ticker. nginx reads the renewed leaf on its next TLS
handshake, so this sidecar signals nothing. Takes root and getCert, the front
door's san or sanFile, publicTLSArgs, and the args and mounts it adds.
*/}}
{{- define "router.getCertContainers" -}}
{{- $root := .root -}}
{{- $getCert := .getCert -}}
{{- if eq (empty $getCert.san) (empty $getCert.sanFile) -}}
{{- fail (printf "the front door names either getCert.san or getCert.sanFile, not both and not neither: san=%v sanFile=%v" $getCert.san $getCert.sanFile) -}}
{{- end -}}
{{- $mounts := list "- name: discovery\n  mountPath: /discovery" -}}
{{- if ne (include "router.mountInventorySocket" $root) "true" -}}
{{- with include "c8s.attestationApiSocketMount" $root | trim -}}
{{- $mounts = append $mounts . -}}
{{- end -}}
{{- end -}}
{{- with $getCert.mounts -}}
{{- $mounts = append $mounts (toYaml . | trim) -}}
{{- end -}}
{{- $extraArgs := concat (include "router.getCertCommonArgs" (dict "root" $root "getCert" $getCert) | fromJsonArray) (default list $getCert.args) -}}
{{- if eq (include "router.mountInventorySocket" $root) "true" -}}
{{- /* get-cert redeems a sandbox token from the node inventory over its
       compiled socket path (workloadclaims.SidecarSocketDir), so node-CVM
       mounts the inventory socket directory there. The deployment adds the
       hostPath volume and the socket's supplemental group
       (workloadclaims.InventorySocketGID) on the same condition. */ -}}
{{- $mounts = append $mounts "- name: workload-claims\n  mountPath: /run/c8s/workload-claims\n  readOnly: true" -}}
{{- else -}}
{{- /* INVARIANT: the flag goes with the absent mount. The router is a chart
       component, not an injected workload: on a cluster whose nodes run no
       admission inventory there is nothing to redeem a sandbox token at, and
       its leaf carries no workload instance. */ -}}
{{- $extraArgs = append $extraArgs "--no-workload-claims" -}}
{{- end -}}
{{- include "c8s.getCertContainers" (dict
  "root" $root
  "attestationApiURL" (include "router.credentialsVerifierURL" $root)
  "san" $getCert.san
  "sanFile" $getCert.sanFile
  "renewInterval" $root.Values.router.certProvisioning.renewInterval
  "extraArgs" $extraArgs
  "extraMounts" (join "\n" $mounts)
) -}}
{{- end }}
