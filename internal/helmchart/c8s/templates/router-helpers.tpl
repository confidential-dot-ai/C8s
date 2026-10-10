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
The router.san list, defaulted. Empty -> the chart-managed Service DNS name
(<release>-router.c8s-router.svc) as a single entry. The first entry is the
CDS mesh-cert identity (see router.san); the whole list is joined into nginx
server_name by router-configmap.yaml. Fails if san is set but not a list.
*/}}
{{- define "router.sanList" -}}
{{- $san := .Values.router.san -}}
{{- if not (kindIs "slice" $san) -}}
{{- fail (printf "router.san must be a list of hostnames, got %s: %v" (kindOf $san) $san) -}}
{{- end -}}
{{- if $san -}}
{{- toJson $san -}}
{{- else -}}
{{- toJson (list (printf "%s.%s.svc" (include "router.fullname" .) (include "c8s.routerMeshNamespace" .))) -}}
{{- end -}}
{{- end -}}

{{/*
The single identity baked into the CDS-issued mesh cert (get-cert) and validated
by cds.dnsSanPatterns: the first entry of router.sanList. Extra san entries
widen only nginx server_name, not the mesh cert.
*/}}
{{- define "router.san" -}}
{{- first (include "router.sanList" . | fromJsonArray) -}}
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
Derive an SNI/verification name from a host:port upstream address.
*/}}
{{- define "router.serverNameFromAddress" -}}
{{- $serverName := regexReplaceAll `^\[([^\]]+)\](?::[0-9]+)?$` . "${1}" -}}
{{- regexReplaceAll `^([^:]+)(?::[0-9]+)?$` $serverName "${1}" -}}
{{- end -}}

{{/*
router.requireSecuredBackend fails the render on a proxied backend hop that is
not authenticated: plaintext http. A confidential platform has exactly two
safe paths to a backend and this helper admits only them: an adopted workload
(a mesh-wrapped headless Service, validated separately), or an https backend
that terminates TLS itself and is verified against the mesh CA (app-TLS).
There is no plaintext-to-unattested escape hatch. Shared by the catch-all
upstream and every route backend so the invariant lives in one place.
Args: protocol, address, label, kind, suggest (leading hint prose, may be "").
*/}}
{{- define "router.requireSecuredBackend" -}}
{{- if ne .protocol "https" -}}
{{- fail (printf "VALIDATION_ERROR kind=%s: %s.address=%q is a plaintext http hop the chart cannot confirm the node mesh wraps. %sUse https so the backend authenticates itself (app-TLS)" .kind .label .address .suggest) -}}
{{- end -}}
{{- end -}}


{{/*
Return true when the built-in /allowlist route renders: allowlist.enabled is a
real bool set to true and no legacy typed route owns /allowlist. The nginx
locations, the loopback proxy sidecar, and the Service traffic policy must all
flip on this one predicate.
*/}}
{{- define "router.renderAllowlistRoute" -}}
{{- if not (kindIs "bool" .Values.router.allowlist.enabled) -}}
{{- fail (printf "router.allowlist.enabled must be a boolean; do not set it via --set-string, got: %v" .Values.router.allowlist.enabled) -}}
{{- end -}}
{{- and .Values.router.allowlist.enabled (ne (include "router.hasExplicitAllowlistRoute" .) "true") -}}
{{- end -}}

{{/*
Return true when a legacy typed route owns /allowlist. Such a route suppresses
both the built-in nginx locations and their loopback proxy sidecar.
*/}}
{{- define "router.hasExplicitAllowlistRoute" -}}
{{- $found := false -}}
{{- range $route := .Values.router.routes -}}
{{- $path := toString (default "" $route.path) -}}
{{- if or (eq $path "/allowlist") (eq $path "/allowlist/") -}}
{{- $found = true -}}
{{- end -}}
{{- end -}}
{{- $found -}}
{{- end -}}

{{/*
Validate a per-route CORS override. Only the `enabled` field is honored;
shared knobs live on router.cors. Args: dict { "cors": route.cors, "label": ... }.
*/}}
{{- define "router.validateRouteCORS" -}}
{{- if .cors -}}
{{- $cors := .cors -}}
{{- range $k, $_ := $cors -}}
{{- if ne $k "enabled" -}}
{{- fail (printf "%s.cors only supports the `enabled` field; remove %q (configure shared CORS knobs under router.cors)" $.label $k) -}}
{{- end -}}
{{- end -}}
{{- if hasKey $cors "enabled" -}}
{{- if not (kindIs "bool" $cors.enabled) -}}
{{- fail (printf "%s.cors.enabled must be a boolean; do not set it via --set-string, got: %v" $.label $cors.enabled) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Selector labels.
*/}}
{{- define "router.selectorLabels" -}}
app.kubernetes.io/name: {{ include "router.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
The validated public front-door mode: cds | webpki | acme. Fails the render on
a mode/values mismatch: webpki needs the Secret and is the only mode that may
carry one; acme needs a TEE-held key (node-CVM), a reachable :80
challenge, and HTTP-01-issuable sanList entries.
*/}}
{{- define "router.publicTLSMode" -}}
{{- $mode := printf "%v" .Values.router.publicTLS.mode -}}
{{- if not (has $mode (list "cds" "webpki" "acme")) -}}
{{- fail (printf "router.publicTLS.mode must be cds, webpki, or acme, got: %s" $mode) -}}
{{- end -}}
{{- if and (eq $mode "webpki") (not .Values.router.publicTLS.secretName) -}}
{{- fail "router.publicTLS.mode=webpki requires router.publicTLS.secretName" -}}
{{- end -}}
{{- if and (ne $mode "webpki") .Values.router.publicTLS.secretName -}}
{{- fail (printf "router.publicTLS.secretName is set but router.publicTLS.mode is %q; set mode=webpki to serve the Secret, or clear secretName" $mode) -}}
{{- end -}}
{{- if eq $mode "acme" -}}
{{- if not (eq .Values.attestationApi.cvmMode "bare-metal") -}}
{{- fail "VALIDATION_ERROR kind=router_acme_runtime: router.publicTLS.mode=acme requires a confidential runtime (attestationApi.cvmMode=bare-metal) so the ACME account and serving keys are TEE-held" -}}
{{- end -}}

{{- range $s := (include "router.sanList" . | fromJsonArray) -}}
{{- if contains "*" $s -}}
{{- fail (printf "router.publicTLS.mode=acme cannot issue for wildcard san %q: HTTP-01 forbids wildcards" $s) -}}
{{- end -}}
{{- end -}}
{{- if and (not .Values.router.hostPort.enabled) (eq .Values.router.service.type "ClusterIP") -}}
{{- fail "VALIDATION_ERROR kind=router_acme_front_door: router.publicTLS.mode=acme needs an internet-reachable front door for the HTTP-01 challenge: set router.service.type=LoadBalancer (any LB implementation: cloud controller, MetalLB, kube-vip, ...) or router.hostPort.enabled=true" -}}
{{- end -}}
{{- end -}}
{{- $mode -}}
{{- end -}}

{{/*
The ports the front door image binds (internal/cmds/router): the TLS listener,
and the :80 server the HTTP-01 challenge arrives on in acme mode. Every chart
site that names a port includes these.

INVARIANT: equal to the listeners the enforcer compiles for the router role
(internal/cmds/nri-image-policy routerListeners), together with the acme
sidecar's readiness port below.
*/}}
{{- define "router.httpsPort" -}}8443{{- end -}}
{{- define "router.httpPort" -}}8080{{- end -}}

{{/*
ACME constants shared by the acme sidecar args, the deployment mounts, and the
cert-path helpers below. The ports the sidecar answers on are the front door
image's own (internal/cmds/router).
*/}}
{{- define "router.acmeCertDir" -}}/etc/c8s-acme-tls{{- end -}}
{{/* The serving key and the ACME account key, which the front door alone
     mounts: every other reader of this credential takes the chain above. */}}
{{- define "router.acmeKeyDir" -}}/etc/c8s-acme-key{{- end -}}
{{- define "router.acmeReadyPort" -}}8403{{- end -}}

{{/*
The directory the publicTLS Secret is mounted on (webpki). A Secret arrives as
operator-supplied data, whose destination the enforcer requires below
/mnt/c8s-data (pkg/allowlist), and the measured base pins this one.
*/}}
{{- define "router.publicTLSDir" -}}/mnt/c8s-data/public-tls{{- end -}}

{{/*
Path to the public-TLS certificate nginx serves: the publicTLS Secret
(webpki), the sidecar-issued ACME leaf (acme), or the CDS-issued cert under
the member credential volume (cds).
*/}}
{{- define "router.publicCertPath" -}}
{{- $mode := include "router.publicTLSMode" . -}}
{{- if eq $mode "webpki" -}}
{{- printf "%s/%s" (include "router.publicTLSDir" .) .Values.router.publicTLS.certKey -}}
{{- else if eq $mode "acme" -}}
{{- printf "%s/cert.pem" (include "router.acmeCertDir" .) -}}
{{- else -}}
{{- include "c8s.certFile" . -}}
{{- end -}}
{{- end -}}

{{- define "router.publicKeyPath" -}}
{{- $mode := include "router.publicTLSMode" . -}}
{{- if eq $mode "webpki" -}}
{{- printf "%s/%s" (include "router.publicTLSDir" .) .Values.router.publicTLS.keyKey -}}
{{- else if eq $mode "acme" -}}
{{- printf "%s/key.pem" (include "router.acmeKeyDir" .) -}}
{{- else -}}
{{- include "c8s.keyFile" . -}}
{{- end -}}
{{- end -}}

{{/*
The volume the certificate sidecar writes the discovery document to and the
front door serves it from. Both lanes mount it at this constant, which the
measured base pins.
*/}}
{{- define "router.discoveryDir" -}}/discovery{{- end -}}

{{- define "router.discoveryFilePath" -}}
{{- printf "%s/%s" (include "router.discoveryDir" .) .Values.router.discovery.fileName -}}
{{- end -}}

{{/*
router's discovery + verbose get-cert args, as a YAML list (one arg per line)
for c8s.getCertContainers' extraArgs. router owns its own cert provisioning,
so it adds discovery output and verbose logging to the shared get-cert flow.
*/}}
{{- define "router.getCertCommonArgs" -}}
{{- if .Values.router.discovery.enabled }}
- --discovery-out={{ include "router.discoveryFilePath" . }}
- --discovery-cds-cert-url={{ .Values.router.discovery.cdsCertPath }}
- --discovery-public-tls-mode={{ include "router.publicTLSMode" . }}
{{- if .Values.router.meshCA.expose }}
- --discovery-mesh-ca-url={{ .Values.router.discovery.meshCAPath }}
{{- end }}
{{- end }}
{{- with .Values.router.certProvisioning.caWatchInterval }}
- --ca-watch-interval={{ . }}
{{- end }}
{{- if .Values.router.certProvisioning.verbose }}
- --verbose
{{- end }}
{{- end }}

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
and renews it on a ticker. nginx's own entrypoint reloads on the renewal, so
this sidecar signals nothing. Caller nindents into the Pod spec's initContainers
list.
*/}}
{{- define "router.getCertContainers" -}}
{{- /* Mounted whichever way router.discovery.enabled is set, like the front
       door's own mount, so one measured mount set covers both. */ -}}
{{- $mounts := list (printf "- name: discovery\n  mountPath: %s" (include "router.discoveryDir" .)) -}}
{{- if and (include "c8s.attestationApiSocketPresent" .) (ne (include "router.mountInventorySocket" .) "true") -}}
{{- $mounts = append $mounts (printf "- name: attestation-api-socket\n  mountPath: %s\n  readOnly: true" .Values.nriImagePolicy.hostPaths.runtimeDir) -}}
{{- end -}}
{{- $extraArgs := include "router.getCertCommonArgs" . | fromYamlArray -}}
{{- $sanFile := "" -}}
{{- if .Values.node.baked -}}
{{- $mounts = append $mounts (include "c8s.nodeConfigMount" . | trim) -}}
{{- $sanFile = "/run/c8s-node/tls-san" -}}
{{- end -}}
{{- if eq (include "router.mountInventorySocket" .) "true" -}}
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
{{- if eq (include "router.publicTLSMode" .) "webpki" -}}
{{- $mounts = append $mounts (printf "- name: public-tls\n  mountPath: %s\n  readOnly: true" (include "router.publicTLSDir" .)) -}}
{{- end -}}
{{- include "c8s.getCertContainers" (dict
  "root" .
  "attestationApiURL" (include "router.credentialsVerifierURL" .)
  "san" (include "router.san" .)
  "sanFile" $sanFile
  "renewInterval" .Values.router.certProvisioning.renewInterval
  "extraArgs" $extraArgs
  "extraMounts" (join "\n" $mounts)
) -}}
{{- end }}

{{/*
router.meshWrappedUpstream — "true" when the address is an operator-managed
headless Service (c8s-<id>.<ns>.svc.cluster.local:<port>, the exact
webhook.WorkloadServiceFQDN form). c8s-<id> is a DNS-1035 label, <ns> a
DNS-1123 label. That shape is the one upstream whose backing pod IPs churn, so
it is dialed through a variable and re-resolved per request; every other
address gets a static upstream block resolved once at startup. validations.yaml
(kind=workload_https_upstream, kind=router_unsecured_upstream) branches on the
same predicate. Call with the address string.
*/}}
{{- define "router.meshWrappedUpstream" -}}
{{- if regexMatch "^c8s-[a-z]([-a-z0-9]*[a-z0-9])?\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?\\.svc\\.cluster\\.local:[0-9]+$" . -}}
true
{{- end -}}
{{- end -}}

{{/*
router.nginxArgs — the typed inputs the front door image renders its nginx
configuration from, as a YAML list (internal/cmds/router). Nothing here is an
nginx directive: the image validates every value and owns the template.
Caller nindents into the nginx container's args.
*/}}
{{- define "router.nginxArgs" -}}
{{- $upstreamAddress := .Values.router.upstream.address | trim -}}
{{- $cors := .Values.router.cors -}}
{{- if .Values.node.baked }}
{{- /* The sole virtual host accepts the launch-signed SAN, which the
       certificate sidecar reads from the verified host file at runtime. */}}
- --san=_
{{- /* A baked node's arguments are fixed at image build, so its route data
       comes from the mounted file instead. */}}
- --routes-file={{ include "router.routesFile" . }}
{{- else }}
{{- range $san := (include "router.sanList" . | fromJsonArray) }}
- --san={{ $san }}
{{- end }}
{{- end }}
- --public-cert={{ include "router.publicCertPath" . }}
- --public-key={{ include "router.publicKeyPath" . }}
- --cert={{ include "c8s.certFile" . }}
- --key={{ include "c8s.keyFile" . }}
- --mesh-ca={{ include "c8s.caFile" . }}
{{- /* The baked lane always names the resolver: a backend its routes file
       gains at runtime is a name the image was not built with. */}}
{{- if or $upstreamAddress .Values.router.routes .Values.node.baked }}
- --resolver={{ include "c8s.router.resolver" . }}
{{- end }}
{{- $readTimeout := toString (required "router.upstream.readTimeout is required" .Values.router.upstream.readTimeout) }}
{{- if not (regexMatch `^[0-9]+(ms|s|m|h|d)?$` $readTimeout) }}
{{- fail (printf "router.upstream.readTimeout must be an nginx time such as 3600s or 60m, got: %s" $readTimeout) }}
{{- end }}
- --backend-read-timeout={{ $readTimeout }}
{{- if and $upstreamAddress (not .Values.node.baked) }}
- --backend={{ $upstreamAddress }}
- --backend-protocol={{ .Values.router.upstream.protocol }}
{{- with .Values.router.upstream.serverName }}
- --backend-server-name={{ . }}
{{- end }}
{{- end }}
{{- if not .Values.node.baked }}
{{- range $i, $route := .Values.router.routes }}
- --route={{ include "router.routeFields" (dict "route" $route "index" $i) }}
{{- end }}
{{- end }}
{{- if .Values.router.attest.enabled }}
- --attest-port={{ .Values.router.attest.port }}
{{- end }}
{{- if eq (include "router.renderAllowlistRoute" .) "true" }}
{{- $allowlist := .Values.router.allowlist }}
- --allowlist-proxy-port={{ include "c8s.int" $allowlist.proxyPort }}
- --allowlist-write-rate={{ include "c8s.int" $allowlist.rateLimit.requestsPerSecond }}
- --allowlist-write-burst={{ include "c8s.int" $allowlist.rateLimit.burst }}
- --allowlist-write-total-rate={{ include "c8s.int" $allowlist.rateLimit.totalRequestsPerSecond }}
- --allowlist-write-total-burst={{ include "c8s.int" $allowlist.rateLimit.totalBurst }}
- --allowlist-read-rate={{ include "c8s.int" $allowlist.readRateLimit.requestsPerSecond }}
- --allowlist-read-burst={{ include "c8s.int" $allowlist.readRateLimit.burst }}
{{- end }}
{{- if .Values.router.discovery.enabled }}
- --discovery-path={{ .Values.router.discovery.path }}
- --discovery-file={{ include "router.discoveryFilePath" . }}
- --discovery-cds-cert-path={{ .Values.router.discovery.cdsCertPath }}
{{- if .Values.router.meshCA.expose }}
- --discovery-mesh-ca-path={{ .Values.router.discovery.meshCAPath }}
{{- end }}
{{- end }}
{{- if $cors.allowOrigins }}
{{- range $origin := $cors.allowOrigins }}
- --cors-allow-origin={{ $origin }}
{{- end }}
{{- range $method := $cors.allowMethods }}
- --cors-allow-method={{ $method }}
{{- end }}
{{- range $header := $cors.allowHeaders }}
- --cors-allow-header={{ $header }}
{{- end }}
{{- range $header := $cors.exposeHeaders }}
- --cors-expose-header={{ $header }}
{{- end }}
{{- if $cors.allowCredentials }}
- --cors-allow-credentials
{{- end }}
- --cors-max-age={{ include "c8s.int" $cors.maxAge }}
{{- end }}
{{- if eq (include "router.publicTLSMode" .) "acme" }}
- --acme
{{- end }}
{{- end -}}

{{/*
router.routeFields — one router.routes entry as the image's --route field
list. A comma separates the fields and an equals sign separates a field's name
from its value, so a value carrying either could add a field: the render fails
on both, and the image refuses a repeated field as well.
Args: route, index (for the failure message).
*/}}
{{- define "router.routeFields" -}}
{{- $route := .route -}}
{{- /* validations.yaml names a missing path, backend or address. */ -}}
{{- $backend := default dict $route.backend -}}
{{- $address := default "" $backend.address -}}
{{- $path := default "" $route.path -}}
{{- $values := dict "path" $path "backend" $address "match" (default "prefix" $route.match) "protocol" (default "http" $backend.protocol) "server-name" (default "" $backend.serverName) -}}
{{- range $field, $value := $values -}}
{{- if regexMatch `[,=]` (toString $value) -}}
{{- fail (printf "VALIDATION_ERROR kind=router_route_field: router.routes[%d] %s=%q must not contain ',' or '=': each route crosses to the front door as one comma-separated field list" $.index $field $value) -}}
{{- end -}}
{{- end -}}
{{- $fields := list (printf "path=%s" $path) (printf "backend=%s" $address) -}}
{{- $fields = append $fields (printf "match=%s" (default "prefix" $route.match)) -}}
{{- $fields = append $fields (printf "protocol=%s" (default "http" $backend.protocol)) -}}
{{- with $backend.serverName -}}
{{- $fields = append $fields (printf "server-name=%s" .) -}}
{{- end -}}
{{- if and (hasKey $route "cors") (hasKey (default dict $route.cors) "enabled") -}}
{{- $fields = append $fields (printf "cors=%v" $route.cors.enabled) -}}
{{- end -}}
{{- join "," $fields -}}
{{- end -}}

{{/*
The front door's route data as typed JSON, the same values router.nginxArgs
passes as flags. The baked lane reads it from the mounted file instead, since
a baked node's args cannot be edited after the image is built.
*/}}
{{- define "router.routesJSON" -}}
{{- $backend := dict -}}
{{- with .Values.router.upstream.address | trim -}}
{{- $backend = dict "address" . "protocol" $.Values.router.upstream.protocol -}}
{{- with $.Values.router.upstream.serverName -}}
{{- $backend = merge $backend (dict "serverName" .) -}}
{{- end -}}
{{- end -}}
{{- $routes := list -}}
{{- range $i, $route := .Values.router.routes -}}
{{- $r := dict "path" $route.path "match" (default "prefix" $route.match) -}}
{{- $b := dict "address" $route.backend.address "protocol" (default "http" $route.backend.protocol) -}}
{{- with $route.backend.serverName -}}
{{- $b = merge $b (dict "serverName" .) -}}
{{- end -}}
{{- $r = merge $r (dict "backend" $b) -}}
{{- if and (hasKey $route "cors") (hasKey (default dict $route.cors) "enabled") -}}
{{- $r = merge $r (dict "cors" $route.cors.enabled) -}}
{{- end -}}
{{- $routes = append $routes $r -}}
{{- end -}}
{{- $file := dict "routes" $routes -}}
{{- if $backend -}}
{{- $file = merge $file (dict "backend" $backend) -}}
{{- end -}}
{{- $file | toPrettyJson -}}
{{- end -}}

{{/*
The mount the front door reads its route data from. A ConfigMap is observed as
operator-supplied data, so the destination is below the reserved data prefix
(pkg/allowlist.DataMountPrefix) and the measured base pins it there by volume
name.
*/}}
{{- define "router.routesDir" -}}/mnt/c8s-data/router-routes{{- end -}}
{{- define "router.routesFile" -}}{{ include "router.routesDir" . }}/routes.json{{- end -}}
