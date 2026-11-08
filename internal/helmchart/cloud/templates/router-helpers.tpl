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
The single identity baked into the CDS-issued mesh cert (get-cert), which the
CDS's own leaf DNS rules must admit: the first entry of router.sanList. Extra
san entries widen only nginx server_name, not the mesh cert.
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
The validated rate-limit bounds of the built-in /allowlist route, as a JSON
dict: the nginx zone rates and the bursts each location applies. The budget
invariants between them live in validations.yaml
(kind=router_allowlist_rate_budget).
*/}}
{{- define "router.allowlistLimits" -}}
{{- $limits := .Values.router.allowlist -}}
{{- dict
  "readBurst" (include "c8s.positiveInt" (dict "value" $limits.readRateLimit.burst "label" "router.allowlist.readRateLimit.burst") | int)
  "readRate" (include "c8s.positiveInt" (dict "value" $limits.readRateLimit.requestsPerSecond "label" "router.allowlist.readRateLimit.requestsPerSecond") | int)
  "writeBurst" (include "c8s.positiveInt" (dict "value" $limits.rateLimit.burst "label" "router.allowlist.rateLimit.burst") | int)
  "writeRate" (include "c8s.positiveInt" (dict "value" $limits.rateLimit.requestsPerSecond "label" "router.allowlist.rateLimit.requestsPerSecond") | int)
  "writeTotalBurst" (include "c8s.positiveInt" (dict "value" $limits.rateLimit.totalBurst "label" "router.allowlist.rateLimit.totalBurst") | int)
  "writeTotalRate" (include "c8s.positiveInt" (dict "value" $limits.rateLimit.totalRequestsPerSecond "label" "router.allowlist.rateLimit.totalRequestsPerSecond") | int)
  | toJson -}}
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
readBurst — the numeric args arrive pre-validated by router.allowlistLimits.
*/}}
{{- define "router.allowlistLocation" -}}
{{- $root := .root -}}
location{{ if .exact }} ={{ end }} {{ .path }} {
    {{- include "router.protocolCorsLocationDirectives" $root | nindent 4 }}
    # Holds no attest-lb binding: the connection stays open only while it is
    # younger than keepalive_time (see the discovery location).
    keepalive_time 1m;
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
Render wide-open CORS directives for a C8s protocol-owned location (the
attestation/tunnel namespace, the discovery document and
certificate endpoints, the built-in allowlist route). These endpoints exist
to be verified by any browser anywhere: every response is either
self-authenticating (hardware evidence, CDS-signed certificates, sealed
tunnel records) or public by design, and no request relies on ambient
browser credentials (allowlist mutations are operator-signed over method,
path, and body). An origin allowlist here cannot protect anything and only
breaks third-party verifiers, so the policy is a constant: any origin, no
credentials. Caller nindents into a `location {}` block.
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
"true" on a baked node: its signed launch file supplies the public hostnames
and front-door mode at runtime, through the files nodeservices writes under
/run/c8s-node/router.
*/}}
{{- define "router.launchDriven" -}}
{{- if .Values.node.baked -}}true{{- end -}}
{{- end -}}

{{/*
"true" when the pod runs the acme sidecar and nginx's :80 server: on a baked
node, where the sidecar issues for the launch hostnames, or stands by when the
launch file names none.
*/}}
{{- define "router.acmeSidecar" -}}
{{- include "router.launchDriven" . -}}
{{- end -}}

{{- define "router.launchDir" -}}/run/c8s-node/router{{- end -}}

{{/*
Where nginx reads nginx.conf, and on a baked node the tls-cds.conf and
tls-acme.conf snippets the launch file's tls.conf includes: the nginx
ConfigMap, or on a baked node the image directory mkosi.sync installs them in
(images/node-guest/worker/mkosi.sync), mounted read-only from the measured /usr
instead of a ConfigMap the control plane can edit.
*/}}
{{- define "router.configDir" -}}
{{- if .Values.node.baked -}}{{ include "router.bakedNginxDir" . }}{{- else -}}/mnt/c8s-data/nginx{{- end -}}
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

{{/* Where nginx spools tunnel request bodies (router.nginx.tunnelBodySpace). */}}
{{- define "router.tunnelBodyDir" -}}/var/lib/c8s-tunnel-body{{- end -}}

{{/* nodeservices.RouterTLSSnippetDir must equal it. */}}
{{- define "router.bakedNginxDir" -}}/usr/lib/c8s/router-nginx{{- end -}}

{{/*
ACME constants shared by the acme sidecar args, the deployment mounts, the
nginx :80 server, and the cert-path helpers below.
*/}}
{{- define "router.acmeCertDir" -}}/etc/c8s-acme-tls{{- end -}}
{{- define "router.acmeChallengePort" -}}8402{{- end -}}
{{- define "router.acmeHTTPPort" -}}8080{{- end -}}

{{/* The serving key and the ACME account key, which the front door alone
     mounts: every other reader of this credential takes the chain above. */}}
{{- define "router.acmeKeyDir" -}}/etc/c8s-acme-key{{- end -}}
{{- define "router.acmeReadyPort" -}}8403{{- end -}}

{{- define "router.discoveryFilePath" -}}/discovery/discovery.json{{- end -}}

{{/* The paths nginx serves itself: the discovery document and the two
     certificate endpoints it points at. */}}
{{- define "router.discoveryPath" -}}/v1/discovery{{- end -}}
{{- define "router.cdsCertPath" -}}/.well-known/cds-cert.pem{{- end -}}
{{- define "router.meshCAPath" -}}/.well-known/mesh-ca.pem{{- end -}}

{{/* nginx's TLS listener, which the node's host port 443 and the Service port
     443 forward to; unprivileged, since nginx drops every capability. */}}
{{- define "router.nginxHTTPSPort" -}}8443{{- end -}}

{{/* Loopback port of the armTLS-verifying allowlist proxy; no pod or Service
     port reaches it. */}}
{{- define "router.allowlistProxyPort" -}}8801{{- end -}}

{{/*
router's discovery + verbose get-cert args, as a YAML list (one arg per line)
for c8s.getCertContainers' extraArgs. router owns its own cert provisioning,
so it adds discovery output and verbose logging to the shared get-cert flow.
*/}}
{{- define "router.getCertCommonArgs" -}}
- --discovery-out={{ include "router.discoveryFilePath" . }}
- --discovery-cds-cert-url={{ include "router.cdsCertPath" . }}
{{- if eq (include "router.launchDriven" .) "true" }}
- --discovery-public-tls-mode-file={{ include "router.launchDir" . }}/front-door-mode
- --discovery-public-tls-hostnames-file={{ include "router.launchDir" . }}/hostnames
{{- else }}
- --discovery-public-tls-mode=cds
{{- end }}
- --discovery-mesh-ca-url={{ include "router.meshCAPath" . }}
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
router.cdsAttestArgs takes (dict "root" $).
*/}}
{{- define "router.cdsAttestArgs" -}}
{{- $root := .root -}}
{{- $v := $root.Values.router -}}
{{- $launchDriven := eq (include "router.launchDriven" $root) "true" -}}
{{- /* Loopback only: every endpoint (/healthz, /readyz, both attest routes,
       /tunnel) sits on one listener; nginx proxies /readyz to it. The routing
       listener is loopback too: nginx terminates public TLS first. */ -}}
{{- $args := list "cds-attest" "--host=127.0.0.1" (printf "--port=%v" $v.attest.port) -}}
{{- $args = concat $args (list (printf "--platform=%v" $v.attest.platform) (printf "--generation=%v" $v.attest.generation)) -}}
{{- $args = append $args (printf "--attestation-api-url=%s" (default (include "c8s.attestationApiURL" $root) $v.attest.attestationApiURL)) -}}
{{- if $launchDriven -}}
{{- $args = append $args (printf "--front-door-mode-file=%s/front-door-mode" (include "router.launchDir" $root)) -}}
{{- else -}}
{{- $args = append $args "--front-door-mode=cds" -}}
{{- end -}}
{{- /* The mesh identity leaf nginx presents in cds mode, which attest-lb
       binds; in acme mode attest-lb binds the ACME leaf a direct-TLS client
       sees. */ -}}
{{- $args = append $args (printf "--serving-cert-file=%s" (include "c8s.certFile" $root)) -}}
{{- if $launchDriven -}}
{{- $args = append $args (printf "--acme-serving-cert-file=%s/cert.pem" (include "router.acmeCertDir" $root)) -}}
{{- end -}}
{{- /* The NRI plugin's measured-policy journal, under the
       attestation-api-socket mount; an absent journal omits the list. */ -}}
{{- if include "c8s.attestationApiSocketPresent" $root -}}
{{- $args = append $args (printf "--measured-policies-file=%s/measured-policies" $root.Values.nriImagePolicy.hostPaths.runtimeDir) -}}
{{- end -}}
{{- /* Route by the operator-signed manifest polled from the verified CDS:
       application requests from nginx on --routing-port, and requests
       decrypted from the tunnel. The enforcer mounts the one CDS endpoint
       this node admits for the router role, so the chart names none. */ -}}
{{- $args = concat $args (include "router.cdsPinArgs" $root | fromJsonArray) -}}
{{- /* Operator keys: the launch configuration on a baked node, where
       naming it makes a missing file fatal, else cds.operatorKeys, else
       CDS's GET /operator-keys (route policy W6; docs/operator.md, Route
       manifest). cds-attest prefers the launch configuration whenever it
       finds it. */ -}}
{{- if not (include "c8s.cdsFromValues" $root) -}}
{{- $args = append $args "--operator-keys-file=/run/c8s-node/operator-pubkey" -}}
{{- else if $root.Values.cds.operatorKeys -}}
{{- $args = append $args "--operator-keys-file=/mnt/c8s-data/operator-keys/keys.pem" -}}
{{- end -}}
{{- $args = append $args (printf "--routes-poll-interval=%v" $v.routing.pollInterval) -}}
{{- $args = append $args "--routing-host=127.0.0.1" -}}
{{- $args = append $args (printf "--routing-port=%s" (include "router.routingPort" $root)) -}}
{{- $args = append $args (printf "--backend-timeout=%v" $v.routing.backendTimeout) -}}
{{- with $v.routing.tunnelBudget -}}
{{- if not (regexMatch `^[1-9][0-9]*(Ki|Mi|Gi|Ti|k|M|G|T)?$` (toString .)) -}}
{{- fail (printf "router.routing.tunnelBudget must be a quantity of bytes such as 64Gi, got: %v" .) -}}
{{- end -}}
{{- $args = append $args (printf "--tunnel-budget=%s" .) -}}
{{- end -}}
{{- $args = append $args (printf "--reserved-paths=%s" (include "router.reservedPaths" $root)) -}}
{{- /* Serve the applied signed manifest at /.well-known/c8s/routes for
       clients that check the route digest under pinned operator keys. */ -}}
{{- if dig "routePublication" "enabled" false $v -}}
{{- $args = append $args "--publish-routes" -}}
{{- end -}}
{{- $args | toJson -}}
{{- end -}}

{{/* The proxy holds the credentials role, so the node hands it the one CDS
     its pod may reach and the pins to verify it with, and refuses an argument
     naming either (cmdsutil.ResolveCDSEndpoint, cmdsutil.ResolveCDSPins). */}}
{{- define "router.allowlistProxyArgs" -}}
{{- list "allowlist-proxy" "--host=127.0.0.1" (printf "--port=%s" (include "router.allowlistProxyPort" .)) (printf "--attestation-api-url=%s" (include "router.credentialsVerifierURL" .)) | toJson -}}
{{- end -}}

{{- /* The signed launch file names the domains. With none, the sidecar
       stands by until the mesh leaf exists. */ -}}
{{- define "router.acmeArgs" -}}
{{- $dir := include "router.launchDir" . -}}
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
handshake, so this sidecar signals nothing. Caller nindents into the Pod spec's initContainers
list.
*/}}
{{- define "router.getCertContainers" -}}
{{- $mounts := list "- name: discovery\n  mountPath: /discovery" -}}
{{- if ne (include "router.mountInventorySocket" .) "true" -}}
{{- with include "c8s.attestationApiSocketMount" . | trim -}}
{{- $mounts = append $mounts . -}}
{{- end -}}
{{- end -}}
{{- $extraArgs := include "router.getCertCommonArgs" . | fromYamlArray -}}
{{- $sanFile := "" -}}
{{- if .Values.node.baked -}}
{{- $mounts = append $mounts (include "c8s.nodeConfigMount" . | trim) -}}
{{- $sanFile = "/run/c8s-node/tls-san" -}}
{{- end -}}
{{- if .Values.node.baked -}}
{{- /* Renew past a stamp taken while only part of the pod runs: a baked
       router needs the workload stamp that clients pin. */ -}}
{{- with include "c8s.routerEntryName" . -}}
{{- $extraArgs = append $extraArgs (printf "--expected-workload=%s" .) -}}
{{- end -}}
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
The cds-attest routing listener's loopback port, validated against the other
loopback and nginx ports it shares the pod network namespace with.
*/}}
{{- define "router.routingPort" -}}
{{- $port := include "c8s.int" .Values.router.routing.port | int -}}
{{- if or (lt $port 1) (gt $port 65535) -}}
{{- fail (printf "router.routing.port must be between 1 and 65535, got: %d" $port) -}}
{{- end -}}
{{- $others := dict
  "router.attest.port" .Values.router.attest.port
  "the allowlist proxy port" (include "router.allowlistProxyPort" .)
  "the nginx HTTPS port" (include "router.nginxHTTPSPort" .) -}}
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
or in the tunnel (route policy M6). cds-attest matches each as a path prefix
ending at a segment boundary, and refuses one that is not already normalized.
*/}}
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
The pin a router sidecar verifies this cluster's CDS against, as a JSON list of
container args: the node's signed policy on a baked node, else the mounted
cds.measurementsConfig. Shared by allowlist-proxy and cds-attest, so the relay
and the route manifest poller trust the same CDS.
*/}}
{{- define "router.cdsPinArgs" -}}
{{- $pin := "/run/c8s-node/cds.json" -}}
{{- if include "c8s.cdsFromValues" . -}}{{- $pin = "/mnt/c8s-data/measurements/cds.json" -}}{{- end -}}
{{- list (printf "--image-policy-file=%s" $pin) | toJson -}}
{{- end -}}

{{/* The protocol CORS directives and the blank line that separates them from
     the rest of a location block. */}}
{{- define "router.wellKnownCorsDirectives" -}}
{{- include "router.protocolCorsLocationDirectives" . }}{{ "\n" }}
{{- end -}}

{{/*
router.wellKnownProxyDirectives renders the directives every
/.well-known/c8s/ location shares: CORS, the proxy to cds-attest with
buffering on and no temp-file spill, and the forwarded headers, including
the connection identifier attest-lb binds. Inputs: root (the chart context)
and readTimeout.
*/}}
{{- define "router.wellKnownProxyDirectives" -}}
{{- $root := .root -}}
{{ include "router.wellKnownCorsDirectives" $root -}}
proxy_pass http://127.0.0.1:{{ $root.Values.router.attest.port }};
proxy_buffering on;
proxy_request_buffering on;
proxy_max_temp_file_size 0;
proxy_read_timeout {{ .readTimeout }};
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-C8s-Connection $nginx_start.$pid.$connection;


{{- end -}}

{{/*
router.servedCredentials — the leaf, key and CA get-cert publishes, which the
router serves from. One space-separated list, read by serve.sh.
*/}}
{{- define "router.servedCredentials" -}}
{{ include "c8s.certFile" . }} {{ include "c8s.keyFile" . }} {{ include "c8s.caFile" . }}
{{- end -}}
