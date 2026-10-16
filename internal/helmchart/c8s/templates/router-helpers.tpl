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
(<release>-router.<namespace>.svc) as a single entry. The first entry is the
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
{{- toJson (list (printf "%s.%s.svc" (include "router.fullname" .) .Release.Namespace)) -}}
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
Validate that san contains only safe characters for use in nginx config.
Allows DNS hostnames and wildcards (e.g. *.example.com).
*/}}
{{- define "router.validateSan" -}}
{{- if regexMatch `[^a-zA-Z0-9.*-]` . -}}
{{- fail (printf "san contains invalid characters: %s - only alphanumeric, dots, hyphens, and wildcards are allowed" .) -}}
{{- end -}}
{{- end -}}

{{/*
Return true when the built-in /allowlist route renders: allowlist.enabled is a
real bool set to true. The nginx locations, the loopback proxy sidecar, and the
Service traffic policy must all flip on this one predicate.
*/}}
{{- define "router.renderAllowlistRoute" -}}
{{- if not (kindIs "bool" .Values.router.allowlist.enabled) -}}
{{- fail (printf "router.allowlist.enabled must be a boolean; do not set it via --set-string, got: %v" .Values.router.allowlist.enabled) -}}
{{- end -}}
{{- .Values.router.allowlist.enabled -}}
{{- end -}}

{{/*
Render one half of the built-in CDS allowlist route. The caller emits an exact
/allowlist location and a /allowlist/ prefix location so unrelated paths such
as /allowlisted never reach the loopback proxy. proxy_pass includes $request_uri
explicitly: operator authorization signs the HTTP method, exact path, and body,
so nginx must not normalize or replace the path before CDS verifies the token.

The loopback proxy verifies CDS's armTLS evidence. Stock nginx cannot verify
the attestation extension itself, so it must never dial CDS directly here.

Args: root, exact (bool), path, proxyPort, writeBurst, writeTotalBurst,
readBurst — the numeric args arrive pre-validated by the configmap prologue.
*/}}
{{- define "router.allowlistLocation" -}}
{{- $root := .root -}}
location{{ if .exact }} ={{ end }} {{ .path }} {
    {{- if default false $root.Values.router.cors.enabled }}
    {{- include "router.corsLocationDirectives" $root.Values.router.cors | nindent 4 }}
    {{- else if eq (include "router.protocolCorsEnabled" $root) "true" }}
    {{- include "router.protocolCorsLocationDirectives" $root | nindent 4 }}
    {{- end }}
    # These run before nginx collapses callers onto the loopback proxy source.
    # Each zone's map key is empty for the methods it does not cover, so
    # mutations count per client and in aggregate, reads per client only.
    limit_req zone=allowlist_write_per_client burst={{ .writeBurst }} nodelay;
    limit_req zone=allowlist_write_total burst={{ .writeTotalBurst }} nodelay;
    limit_req zone=allowlist_read_per_client burst={{ .readBurst }} nodelay;
    limit_req_status 429;
    proxy_pass http://127.0.0.1:{{ .proxyPort }}$request_uri;
    proxy_set_header Host $host;
    proxy_set_header Authorization $http_authorization;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
{{- end -}}

{{/*
Validate the global CORS configuration. Skips when disabled.
*/}}
{{- define "router.validateCORS" -}}
{{- $cors := default dict . -}}
{{- if hasKey $cors "enabled" -}}
{{- if not (kindIs "bool" $cors.enabled) -}}
{{- fail (printf "router.cors.enabled must be a boolean; do not set it via --set-string, got: %v" $cors.enabled) -}}
{{- end -}}
{{- end -}}
{{- if hasKey $cors "protocolEndpoints" -}}
{{- if not (kindIs "bool" $cors.protocolEndpoints) -}}
{{- fail (printf "router.cors.protocolEndpoints must be a boolean; do not set it via --set-string, got: %v" $cors.protocolEndpoints) -}}
{{- end -}}
{{- end -}}
{{- if default false $cors.enabled -}}
{{- $origins := default (list) $cors.allowOrigins -}}
{{- if not $origins -}}
{{- fail "router.cors.enabled=true requires router.cors.allowOrigins to be non-empty" -}}
{{- end -}}
{{- range $o := $origins -}}
{{- if not (or (eq $o "*") (regexMatch `^https?://[A-Za-z0-9.-]+(?::[0-9]+)?$` $o)) -}}
{{- fail (printf "router.cors.allowOrigins entry %q must be \"*\" or a scheme://host[:port] URL" $o) -}}
{{- end -}}
{{- end -}}
{{- if and (default false $cors.allowCredentials) (has "*" $origins) -}}
{{- fail "router.cors.allowCredentials=true is incompatible with allowOrigins containing \"*\" (browsers reject this combination)" -}}
{{- end -}}
{{- range $field := list "allowMethods" "allowHeaders" "exposeHeaders" -}}
{{- range $v := default (list) (index $cors $field) -}}
{{- if regexMatch `[\r\n";{}\\]` $v -}}
{{- fail (printf "router.cors.%s entry %q must not contain CR, LF, quotes, semicolons, braces, or backslashes" $field $v) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if hasKey $cors "maxAge" -}}
{{- if not (regexMatch `^[0-9]+$` (printf "%v" $cors.maxAge)) -}}
{{- fail (printf "router.cors.maxAge must be a non-negative integer, got: %v" $cors.maxAge) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Render the http-level CORS maps. `$cors_origin` echoes a matching request
Origin from router.cors.allowOrigins. The remaining maps implement
upstream-pass-through: when the upstream emits Access-Control-Allow-Origin
we adopt its full CORS header set verbatim (so browsers never see duplicate
headers); otherwise we fall back to router's configured values.

Access-Control-Expose-Headers is the one exception: router's configured
exposeHeaders are ALWAYS advertised (and merged in front of upstream's
value when in pass-through mode), so browsers can read custom response
headers the upstream does not know to advertise.

Emitted only when CORS is enabled. Caller nindents into the nginx `http {}`
context.
*/}}
{{- define "router.corsMap" -}}
{{- $cors := default dict .Values.router.cors -}}
{{- if default false $cors.enabled -}}
{{- $origins := default (list) $cors.allowOrigins -}}
{{- $methods := join ", " (default (list "GET" "POST" "OPTIONS") $cors.allowMethods) -}}
{{- $headers := join ", " (default (list "Authorization" "Content-Type" "X-C8s-Session") $cors.allowHeaders) -}}
{{- $exposeHeaders := default (list) $cors.exposeHeaders -}}
{{- $credentials := ternary "true" "" (default false $cors.allowCredentials) }}
map $http_origin $cors_origin {
{{- if has "*" $origins }}
    default "*";
{{- else }}
    default "";
{{- range $o := $origins }}
    "{{ $o }}" "{{ $o }}";
{{- end }}
{{- end }}
}

map $upstream_http_access_control_allow_origin $cors_passthrough {
    default "0";
    "~.+"   "1";
}

map $cors_passthrough $cors_out_origin {
    "0" $cors_origin;
    "1" $upstream_http_access_control_allow_origin;
}

map $cors_passthrough $cors_out_methods {
    "0" "{{ $methods }}";
    "1" $upstream_http_access_control_allow_methods;
}

map $cors_passthrough $cors_out_headers {
    "0" "{{ $headers }}";
    "1" $upstream_http_access_control_allow_headers;
}

map $cors_passthrough $cors_out_credentials {
    "0" "{{ $credentials }}";
    "1" $upstream_http_access_control_allow_credentials;
}

{{- if $exposeHeaders }}
map $upstream_http_access_control_expose_headers $cors_upstream_expose_suffix {
    default "";
    "~.+"   ", $upstream_http_access_control_expose_headers";
}

map $cors_passthrough $cors_out_expose {
    "0" "{{ join ", " $exposeHeaders }}";
    "1" "{{ join ", " $exposeHeaders }}$cors_upstream_expose_suffix";
}
{{- else }}
map $cors_passthrough $cors_out_expose {
    "0" "";
    "1" $upstream_http_access_control_expose_headers;
}
{{- end }}
{{- end -}}
{{- end -}}

{{/*
Render per-location CORS directives. Non-preflight responses go through
$cors_out_* — either the upstream's CORS headers (passed through unchanged)
or router's configured ones, never both. proxy_hide_header drops the
upstream copies so the maps' re-emitted version is the only one on the
wire. Preflight OPTIONS short-circuits at nginx with router's configured
policy. Caller passes the effective CORS dict and guarantees CORS is
enabled. Caller nindents into a `location {}` block.
*/}}
{{- define "router.corsLocationDirectives" -}}
{{- $cors := default dict . -}}
{{- $methods := join ", " (default (list "GET" "POST" "OPTIONS") $cors.allowMethods) -}}
{{- $headers := join ", " (default (list "Authorization" "Content-Type" "X-C8s-Session") $cors.allowHeaders) -}}
{{- $maxAge := default 600 $cors.maxAge }}
proxy_hide_header Access-Control-Allow-Origin;
proxy_hide_header Access-Control-Allow-Methods;
proxy_hide_header Access-Control-Allow-Headers;
proxy_hide_header Access-Control-Allow-Credentials;
proxy_hide_header Access-Control-Expose-Headers;
if ($request_method = 'OPTIONS') {
    add_header Access-Control-Allow-Origin  $cors_origin always;
    add_header Access-Control-Allow-Methods "{{ $methods }}" always;
    add_header Access-Control-Allow-Headers "{{ $headers }}" always;
{{- if default false $cors.allowCredentials }}
    add_header Access-Control-Allow-Credentials "true" always;
{{- end }}
    add_header Access-Control-Max-Age       "{{ $maxAge }}" always;
    add_header Content-Length 0;
    return 204;
}
add_header Access-Control-Allow-Origin      $cors_out_origin always;
add_header Access-Control-Allow-Methods     $cors_out_methods always;
add_header Access-Control-Allow-Headers     $cors_out_headers always;
add_header Access-Control-Allow-Credentials $cors_out_credentials always;
add_header Access-Control-Expose-Headers    $cors_out_expose always;
{{- end -}}

{{/*
Whether the C8s protocol-owned locations get the built-in wide-open CORS
block: router.cors.protocolEndpoints (default true), unless the operator's
global CORS block is enabled — an explicit policy already covers every
location, so the built-in one steps aside. hasKey instead of `default`
because sprig's default treats an explicit false as unset.
*/}}
{{- define "router.protocolCorsEnabled" -}}
{{- $cors := default dict .Values.router.cors -}}
{{- $pe := true -}}
{{- if hasKey $cors "protocolEndpoints" -}}{{- $pe = $cors.protocolEndpoints -}}{{- end -}}
{{- and $pe (not (default false $cors.enabled)) -}}
{{- end -}}

{{/*
Render wide-open CORS directives for a C8s protocol-owned location (the
attestation/tunnel namespace, the discovery document and
certificate endpoints, the built-in allowlist route). These endpoints exist
to be verified by any browser anywhere: every response is either
self-authenticating (hardware evidence, CDS-signed certificates, sealed
tunnel records) or public by design, and no request relies on ambient
browser credentials (allowlist mutations are operator-signed over method,
path, and body). An origin allowlist here cannot protect anything and only
breaks third-party verifiers, so the policy is a constant: any origin, no
credentials. Self-contained on purpose — no http-level maps and no
upstream pass-through; these endpoints are C8s-owned end to end, so router
states their CORS policy itself. Caller nindents into a `location {}`
block.
*/}}
{{- define "router.protocolCorsLocationDirectives" -}}
proxy_hide_header Access-Control-Allow-Origin;
proxy_hide_header Access-Control-Allow-Methods;
proxy_hide_header Access-Control-Allow-Headers;
proxy_hide_header Access-Control-Allow-Credentials;
proxy_hide_header Access-Control-Expose-Headers;
if ($request_method = 'OPTIONS') {
    add_header Access-Control-Allow-Origin  "*" always;
    add_header Access-Control-Allow-Methods "GET, POST, OPTIONS" always;
    add_header Access-Control-Allow-Headers "Authorization, Content-Type, X-C8s-Session" always;
    add_header Access-Control-Max-Age       "600" always;
    add_header Content-Length 0;
    return 204;
}
add_header Access-Control-Allow-Origin "*" always;
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
"true" on a baked node: its signed launch file supplies the public hostnames
and front-door mode at runtime, through the files nodeservices writes under
/run/c8s-node/router. router.publicTLS.mode must stay cds, so a render never
silently ignores it.
*/}}
{{- define "router.launchDriven" -}}
{{- if .Values.node.baked -}}
{{- if ne (printf "%v" .Values.router.publicTLS.mode) "cds" -}}
{{- fail "node.baked takes the public TLS mode from the launch file: leave router.publicTLS.mode at cds" -}}
{{- end -}}
{{- /* The launch file may select acme, so the :80 challenge path must be
       reachable; cvmMode=bare-metal is already required by validations.yaml. */ -}}
{{- if and (not .Values.router.hostPort.enabled) (eq .Values.router.service.type "ClusterIP") -}}
{{- fail "VALIDATION_ERROR kind=router_acme_front_door: node.baked may select ACME from the launch file, which needs an internet-reachable :80 for the HTTP-01 challenge: set router.service.type=LoadBalancer or router.hostPort.enabled=true" -}}
{{- end -}}
true
{{- end -}}
{{- end -}}

{{/*
"true" when the pod runs the acme sidecar and nginx's :80 server: the acme
public TLS mode, or a baked node (where the sidecar issues for the launch
hostnames, or stands by when the launch file names none).
*/}}
{{- define "router.acmeSidecar" -}}
{{- if or (eq (include "router.publicTLSMode" .) "acme") (eq (include "router.launchDriven" .) "true") -}}
true
{{- end -}}
{{- end -}}

{{- define "router.launchDir" -}}/run/c8s-node/router{{- end -}}

{{/*
Where nginx reads nginx.conf, and on a baked node the tls-cds.conf and
tls-acme.conf snippets the launch file's tls.conf includes: the nginx
ConfigMap, or on a baked node the image directory mkosi.sync installs them in
(node-guest-image/c8s/mkosi.sync), mounted read-only from the measured /usr
instead of a ConfigMap the control plane can edit.
*/}}
{{- define "router.configDir" -}}
{{- if .Values.node.baked -}}{{ include "router.bakedNginxDir" . }}{{- else -}}/mnt/c8s-data/nginx{{- end -}}
{{- end -}}

{{/* nodeservices.RouterTLSSnippetDir must equal it. */}}
{{- define "router.bakedNginxDir" -}}/usr/lib/c8s/router-nginx{{- end -}}

{{/*
ACME constants shared by the acme sidecar args, the deployment mounts, the
nginx :80 server, and the cert-path helpers below.
*/}}
{{- define "router.acmeCertDir" -}}/etc/c8s-acme-tls{{- end -}}
{{- define "router.acmeChallengePort" -}}8402{{- end -}}
{{- define "router.acmeHTTPPort" -}}8080{{- end -}}
{{- define "router.acmeReadyPort" -}}8403{{- end -}}

{{/*
Path to the public-TLS certificate nginx serves: the publicTLS Secret
(webpki), the sidecar-issued ACME leaf (acme), or the CDS-issued cert under
tlsMountPath (cds).
*/}}
{{- define "router.publicCertPath" -}}
{{- $mode := include "router.publicTLSMode" . -}}
{{- if eq $mode "webpki" -}}
{{- printf "%s/%s" .Values.router.publicTLS.mountPath .Values.router.publicTLS.certKey -}}
{{- else if eq $mode "acme" -}}
{{- printf "%s/cert.pem" (include "router.acmeCertDir" .) -}}
{{- else -}}
{{- printf "%s/cert.pem" .Values.router.tlsMountPath -}}
{{- end -}}
{{- end -}}

{{- define "router.publicKeyPath" -}}
{{- $mode := include "router.publicTLSMode" . -}}
{{- if eq $mode "webpki" -}}
{{- printf "%s/%s" .Values.router.publicTLS.mountPath .Values.router.publicTLS.keyKey -}}
{{- else if eq $mode "acme" -}}
{{- printf "%s/key.pem" (include "router.acmeCertDir" .) -}}
{{- else -}}
{{- printf "%s/key.pem" .Values.router.tlsMountPath -}}
{{- end -}}
{{- end -}}

{{- define "router.discoveryFilePath" -}}
{{- printf "%s/%s" .Values.router.discovery.mountPath .Values.router.discovery.fileName -}}
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
{{- if eq (include "router.launchDriven" .) "true" }}
- --discovery-public-tls-mode-file={{ include "router.launchDir" . }}/front-door-mode
- --discovery-public-tls-hostnames-file={{ include "router.launchDir" . }}/hostnames
{{- else }}
- --discovery-public-tls-mode={{ include "router.publicTLSMode" . }}
{{- end }}
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
Argv after the c8s image's /c8s entrypoint for the router's c8s-image
containers, as JSON lists. router-deployment.yaml renders them and
c8s.routerEntry pins them in the seed, so the two cannot drift. See
../helpers/allowlist/README.md#router-entry.
router.cdsAttestArgs takes (dict "root" $ "expectedWorkload" <name>).
*/}}
{{- define "router.cdsAttestArgs" -}}
{{- $root := .root -}}
{{- $v := $root.Values.router -}}
{{- $launchDriven := eq (include "router.launchDriven" $root) "true" -}}
{{- /* Loopback only: every endpoint (/healthz, /readyz, both attest routes,
       /tunnel) sits on one listener; nginx proxies /readyz to it. The routing
       listener is loopback too: nginx terminates public TLS first. */ -}}
{{- $args := list "cds-attest" "--host=127.0.0.1" (printf "--port=%v" $v.attest.port) -}}
{{- if not $v.attest.enabled -}}
{{- $args = append $args "--attest-endpoints=false" -}}
{{- end -}}
{{- $args = concat $args (list (printf "--platform=%v" $v.attest.platform) (printf "--generation=%v" $v.attest.generation)) -}}
{{- $args = append $args (printf "--attestation-api-url=%s" (default (include "c8s.attestationApiURL" $root) $v.attest.attestationApiURL)) -}}
{{- /* attest-lb needs a TEE-held serving key (cds, acme); webpki's
       host-visible Secret key stays attest-pq-only. */ -}}
{{- if $launchDriven -}}
{{- $args = append $args (printf "--front-door-mode-file=%s/front-door-mode" (include "router.launchDir" $root)) -}}
{{- else -}}
{{- $args = append $args (printf "--front-door-mode=%s" (include "router.publicTLSMode" $root)) -}}
{{- end -}}
{{- /* The exact leaf nginx presents, so attest-lb report_data commits to the
       DER a direct-TLS client sees. Re-read per request. */ -}}
{{- $args = append $args (printf "--serving-cert-file=%s" (include "router.publicCertPath" $root)) -}}
{{- if $launchDriven -}}
{{- $args = append $args (printf "--acme-serving-cert-file=%s/cert.pem" (include "router.acmeCertDir" $root)) -}}
{{- end -}}
{{- with .expectedWorkload -}}
{{- $args = append $args (printf "--expected-workload=%s" .) -}}
{{- end -}}
{{- /* The identity-bound PQ flow uses the TEE-held mesh credential, never the
       optional publicTLS Secret. */ -}}
{{- $args = append $args (printf "--mesh-identity-cert-file=%s/cert.pem" $v.tlsMountPath) -}}
{{- $args = append $args (printf "--mesh-identity-key-file=%s/key.pem" $v.tlsMountPath) -}}
{{- $args = append $args (printf "--mesh-identity-ca-file=%s/ca.pem" $v.tlsMountPath) -}}
{{- /* Route by the operator-signed manifest polled from the verified CDS:
       application requests from nginx on --routing-port, and requests
       decrypted from the tunnel. */ -}}
{{- $args = append $args (printf "--cds-url=%s" (include "c8s.cdsURL" $root)) -}}
{{- $args = concat $args (include "router.cdsPinArgs" $root | fromJsonArray) -}}
{{- /* Off a baked node the operator keys come from CDS's GET /operator-keys,
       which is control-plane configuration (route policy W6; docs/operator.md,
       Route manifest). */ -}}
{{- if $root.Values.node.baked -}}
{{- $args = append $args "--operator-keys-file=/run/c8s-node/operator-pubkey" -}}
{{- end -}}
{{- $args = append $args (printf "--routes-poll-interval=%v" $v.routing.pollInterval) -}}
{{- $args = append $args "--routing-host=127.0.0.1" -}}
{{- $args = append $args (printf "--routing-port=%s" (include "router.routingPort" $root)) -}}
{{- $args = append $args (printf "--backend-timeout=%v" $v.routing.backendTimeout) -}}
{{- $args = append $args (printf "--tunnel-slots=%s" (include "c8s.positiveInt" (dict "value" $v.routing.tunnelSlots "label" "router.routing.tunnelSlots"))) -}}
{{- $args = append $args (printf "--reserved-paths=%s" (include "router.reservedPaths" $root)) -}}
{{- /* Serve the applied signed manifest at /.well-known/c8s/routes for
       clients that check the route digest under pinned operator keys. */ -}}
{{- if dig "routePublication" "enabled" false $v -}}
{{- $args = append $args "--publish-routes" -}}
{{- end -}}
{{- $args | toJson -}}
{{- end -}}

{{- define "router.allowlistProxyArgs" -}}
{{- $args := list "allowlist-proxy" "--host=127.0.0.1" (printf "--port=%s" (include "c8s.int" .Values.router.allowlist.proxyPort)) (printf "--cds-url=%s" (include "c8s.cdsURL" .)) (printf "--attestation-api-url=%s" (include "c8s.attestationApiURL" .)) -}}
{{- concat $args (include "router.cdsPinArgs" . | fromJsonArray) | toJson -}}
{{- end -}}

{{- define "router.acmeArgs" -}}
{{- $args := list "acme" -}}
{{- if eq (include "router.launchDriven" .) "true" -}}
{{- /* The signed launch file names the domains. With none, the sidecar
       stands by until the mesh leaf exists. */ -}}
{{- $dir := include "router.launchDir" . -}}
{{- $args = append $args (printf "--domains-file=%s/hostnames" $dir) -}}
{{- $args = append $args (printf "--acme-email-file=%s/acme-email" $dir) -}}
{{- $args = append $args (printf "--acme-directory-url-file=%s/acme-directory-url" $dir) -}}
{{- $args = append $args (printf "--standby-cert-dir=%s" .Values.router.tlsMountPath) -}}
{{- else -}}
{{- $args = append $args (printf "--domains=%s" (include "router.sanList" . | fromJsonArray | join ",")) -}}
{{- end -}}
{{- with .Values.router.acme.email -}}
{{- $args = append $args (printf "--acme-email=%s" .) -}}
{{- end -}}
{{- with .Values.router.acme.directoryURL -}}
{{- $args = append $args (printf "--acme-directory-url=%s" .) -}}
{{- end -}}
{{- $args = append $args (printf "--challenge-port=%s" (include "router.acmeChallengePort" .)) -}}
{{- $args = append $args (printf "--http-port=%s" (include "router.acmeHTTPPort" .)) -}}
{{- $args = append $args (printf "--cert-dir=%s" (include "router.acmeCertDir" .)) -}}
{{- $args = append $args (printf "--ready-port=%s" (include "router.acmeReadyPort" .)) -}}
{{- $args | toJson -}}
{{- end -}}

{{/*
The cds-attest readiness gate's workload name. An explicit string wins, and
"" turns the gate off; a c8s-router-* value must be the seeded entry's name.
Unset defaults to the seeded router entry (c8s.routerWorkloadName) where
router.defaultGate holds.
*/}}
{{- define "router.expectedWorkload" -}}
{{- $explicit := .Values.router.attest.expectedWorkload -}}
{{- if not (or (kindIs "string" $explicit) (kindIs "invalid" $explicit)) -}}
{{- fail (printf "router.attest.expectedWorkload must be a string or null, got %s %v" (kindOf $explicit) $explicit) -}}
{{- end -}}
{{- if kindIs "string" $explicit -}}
{{- if and .Values.router.enabled (hasPrefix "c8s-router-" $explicit) -}}
{{- with include "c8s.routerEntryBlocker" . -}}
{{- fail (printf "router.attest.expectedWorkload=%s names the seeded router entry, but these values seed none because %s: leave it unset, or set it to the name of your own router entry" $explicit .) -}}
{{- end -}}
{{- $name := include "c8s.routerWorkloadName" . -}}
{{- if hasKey . "routerNamePlaceholder" -}}
{{- $explicit = $name -}}
{{- else if ne $explicit $name -}}
{{- fail (printf "router.attest.expectedWorkload=%s does not name the seeded router entry, which these values name %s: set it to %s, or leave it unset to follow the entry" $explicit $name $name) -}}
{{- end -}}
{{- end -}}
{{- $explicit -}}
{{- else if eq (include "router.defaultGate" .) "true" -}}
{{- include "c8s.routerWorkloadName" . -}}
{{- end -}}
{{- end -}}

{{/*
"true" when an unset gate defaults on: it can render and be satisfied. The
entry is seeded, hostPort is off, and the node inventory is reachable.
*/}}
{{- define "router.defaultGate" -}}
{{- if and (not (kindIs "string" .Values.router.attest.expectedWorkload)) (eq (include "c8s.routerWorkloadSeeded" .) "true") (not .Values.router.hostPort.enabled) (or .Values.nriImagePolicy.enabled (eq .Values.attestationApi.cvmMode "bare-metal")) -}}
true
{{- end -}}
{{- end -}}

{{/*
"true" when the router pod must mount the node inventory's socket directory:
workload claims are required and this is the node-CVM shape. A baked
router always requests claims so clients can verify its workload stamp.

The condition mirrors the operator's own inventory condition
(operator.yaml): the directory exists only where an installer put it, and a
`type: Directory` hostPath naming a path nothing created wedges the pod in
ContainerCreating. validations.yaml (kind=require_host_image_policy) makes that
condition true in every renderable shape today; the condition is spelled out
anyway so the two consumers of the socket stay on one rule.
*/}}
{{- define "router.mountInventorySocket" -}}
{{- if and (or .Values.node.baked (include "router.expectedWorkload" .)) (or .Values.nriImagePolicy.enabled (eq .Values.attestationApi.cvmMode "bare-metal")) -}}
true
{{- end -}}
{{- end -}}

{{/*
c8s-cert native sidecar (restartPolicy: Always): obtains the leaf on startup
and renews it on a ticker, SIGHUP-ing nginx after each renewal. Caller nindents into the Pod spec's initContainers
list.
*/}}
{{- define "router.getCertContainers" -}}
{{- $mounts := list -}}
{{- if .Values.router.discovery.enabled -}}
{{- $mounts = append $mounts (printf "- name: discovery\n  mountPath: %s" .Values.router.discovery.mountPath) -}}
{{- end -}}
{{- with include "c8s.attestationApiSocketMount" . | trim -}}
{{- $mounts = append $mounts . -}}
{{- end -}}
{{- $extraArgs := include "router.getCertCommonArgs" . | fromYamlArray -}}
{{- $sanFile := "" -}}
{{- if .Values.node.baked -}}
{{- $mounts = append $mounts (include "c8s.nodeConfigMount" . | trim) -}}
{{- $extraArgs = append $extraArgs "--image-policy-file=/run/c8s-node/cds.json" -}}
{{- $sanFile = "/run/c8s-node/tls-san" -}}
{{- end -}}
{{- if or .Values.node.baked (include "router.expectedWorkload" .) -}}

{{- /* A baked router needs the same workload stamp that clients pin, even
       when the optional ingress readiness gate is unset.
       The readiness gate (cds-attest /readyz) demands a matched-workload
       stamp on the mesh leaf, which only exists when get-cert redeems a
       sandbox token from the inventory — so wire the claims flow whenever
       the gate is enabled (the deployment fails the render if the gate is
       set without the sidecar it gates). Node-CVM mounts the inventory
       socket directory at get-cert's compiled path
       (workloadclaims.SidecarSocketDir). The deployment adds the hostPath
       volume and the socket's supplemental group
       (workloadclaims.InventorySocketGID) on the same condition. */ -}}
{{- $extraArgs = append $extraArgs "--workload-claims" -}}
{{- /* Renew past a stamp taken while only part of the pod runs. */ -}}
{{- with include "c8s.routerEntryName" . -}}
{{- $extraArgs = append $extraArgs (printf "--expected-workload=%s" .) -}}
{{- end -}}
{{- if eq (include "router.mountInventorySocket" .) "true" -}}
{{- $mounts = append $mounts "- name: workload-claims\n  mountPath: /run/c8s/workload-claims\n  readOnly: true" -}}
{{- end -}}
{{- end -}}
{{- if eq (include "router.publicTLSMode" .) "webpki" -}}
{{- $mounts = append $mounts (printf "- name: public-tls\n  mountPath: %s\n  readOnly: true" .Values.router.publicTLS.mountPath) -}}
{{- $extraArgs = append $extraArgs (printf "--reload-watch=%s" (include "router.publicCertPath" .)) -}}
{{- $extraArgs = append $extraArgs (printf "--reload-watch=%s" (include "router.publicKeyPath" .)) -}}
{{- end -}}
{{- include "c8s.getCertContainers" (dict
  "root" .
  "san" (include "router.san" .)
  "sanFile" $sanFile
  "certOut" (printf "%s/cert.pem" .Values.router.tlsMountPath)
  "keyOut" (printf "%s/key.pem" .Values.router.tlsMountPath)
  "caOut" (printf "%s/ca.pem" .Values.router.tlsMountPath)
  "volume" "tls-certs"
  "mountPath" .Values.router.tlsMountPath
  "renewInterval" .Values.router.certProvisioning.renewInterval
  "runAsUser" .Values.router.nginx.runAsUser
  "runAsGroup" .Values.router.nginx.runAsGroup
  "runAsNonRoot" .Values.router.nginx.runAsNonRoot
  "reloadNginx" "true"
  "extraArgs" $extraArgs
  "extraMounts" (join "\n" $mounts)
) -}}
{{- end }}

{{/*
The cds-attest routing listener's loopback port, validated against the other
loopback and nginx ports it shares the pod network namespace with.
*/}}
{{- define "router.routingPort" -}}
{{- $port := include "c8s.int" .Values.router.routing.port | int -}}
{{- if or (lt $port 1) (gt $port 65535) -}}
{{- fail (printf "router.routing.port must be between 1 and 65535, got: %d" $port) -}}
{{- end -}}
{{- $others := dict "router.attest.port" .Values.router.attest.port "router.allowlist.proxyPort" .Values.router.allowlist.proxyPort "router.nginx.httpsPort" .Values.router.nginx.httpsPort -}}
{{- if eq (include "router.acmeSidecar" .) "true" -}}
{{- $_ := set $others "the ACME HTTP port" (include "router.acmeHTTPPort" .) -}}
{{- $_ := set $others "the ACME challenge port" (include "router.acmeChallengePort" .) -}}
{{- $_ := set $others "the ACME readiness port" (include "router.acmeReadyPort" .) -}}
{{- end -}}
{{- range $label, $other := $others -}}
{{- if eq $port (include "c8s.int" $other | int) -}}
{{- fail (printf "router.routing.port must differ from %s, got: %d" $label $port) -}}
{{- end -}}
{{- end -}}
{{- $port -}}
{{- end -}}

{{/*
The paths nginx serves itself, as a comma-separated list for cds-attest
--reserved-paths: no manifest route under them is selected, on the public path
or in the tunnel (route policy M6). Listed whether or not each endpoint is
enabled, so a manifest selects the same routes under every chart setting.
cds-attest matches each as a path prefix ending at a segment boundary, and
refuses one that is not already normalized.
*/}}
{{- define "router.reservedPaths" -}}
{{- $paths := list "/allowlist" "/.well-known/c8s/" "/.well-known/acme-challenge/" .Values.router.discovery.path .Values.router.discovery.cdsCertPath .Values.router.discovery.meshCAPath "/readyz" "/healthz" -}}
{{- range $p := $paths -}}
{{- if or (not (regexMatch `^(/[A-Za-z0-9._~-]+)+/?$` $p)) (regexMatch `/\.\.?(/|$)` $p) -}}
{{- fail (printf "router.discovery paths must be absolute paths of letters, digits and ._~- segments, without . or .. segments, got: %s" $p) -}}
{{- end -}}
{{- end -}}
{{- join "," (uniq $paths) -}}
{{- end -}}

{{/*
The CDS measurement pins a router sidecar verifies the chart-managed CDS
against, as a JSON list of container args: the node's signed policy on a baked node, else
cds.measurementsConfig, else cds.measurements and cds.rtmrs. Shared by
allowlist-proxy and cds-attest, so the relay and the route manifest poller
trust the same CDS.
*/}}
{{- define "router.cdsPinArgs" -}}
{{- $args := list -}}
{{- if .Values.node.baked -}}
{{- $args = append $args "--image-policy-file=/run/c8s-node/cds.json" -}}
{{- else if .Values.cds.measurementsConfig -}}
{{- $args = append $args "--image-policy-file=/mnt/c8s-data/measurements/cds.json" -}}
{{- else -}}
{{- with .Values.cds.measurements -}}
{{- $args = append $args (printf "--cds-measurements=%s" (join "," .)) -}}
{{- end -}}
{{- with .Values.cds.rtmrs -}}
{{- $args = append $args (printf "--cds-rtmrs=%s" (join "," .)) -}}
{{- end -}}
{{- end -}}
{{- $args | toJson -}}
{{- end -}}
