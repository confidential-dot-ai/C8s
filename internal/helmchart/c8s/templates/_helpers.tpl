{{/* Common helpers. See ../helpers/common/README.md. */}}

{{- define "c8s.fullname" -}}
{{- printf "%s" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "c8s.operatorName" -}}
{{- printf "%s-operator" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "c8s.attestationApiName" -}}
{{- printf "%s-attestation-api" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "c8s.volumedName" -}}
{{- printf "%s-volumed" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* c8s.cdsPinDocument is the pin an operator passed as content: the
     refvalues document naming the image and launch file this cluster's CDS
     VM proves. A schema below 2 carries no launch file, which is the only
     thing binding that VM to the configuration it serves. */}}
{{- define "c8s.cdsPinDocument" -}}
{{- $document := toString .Values.cds.measurementsConfig -}}
{{- if not $document -}}
{{- fail "VALIDATION_ERROR kind=cds_pins_required: cds.measurementsConfig is empty, so nothing pins the guest identity of this cluster's CDS and nothing dialing it could tell it from any other attested TEE. Pass `c8s install --cds-pin <cds-pin.json>` (written by `c8s cds config new`)." -}}
{{- end -}}
{{- if not (hasPrefix "{" (trim $document)) -}}
{{- fail "VALIDATION_ERROR kind=cds_pin_content: cds.measurementsConfig must be the JSON content of the CDS pin, not a file path — use `c8s install --cds-pin <file>`, `c8s render-values --cds-pin <file>`, or helm --set-file cds.measurementsConfig=<file>" -}}
{{- end -}}
{{- $schema := dig "schema_version" "" (mustFromJson $document) -}}
{{- if ne $schema "2" -}}
{{- fail (printf "VALIDATION_ERROR kind=cds_pin_schema: cds.measurementsConfig is schema_version %q, want \"2\": a CDS is pinned to the launch file it serves, which only schema 2 carries" $schema) -}}
{{- end -}}
{{- $document -}}
{{- end -}}

{{/* c8s.checkCDSAddress refuses an endpoint this cluster's clients could not
     dial: one host, a lowercase DNS name or an IPv4 address, and one port.
     Takes the value. */}}
{{- define "c8s.checkCDSAddress" -}}
{{- $address := toString . -}}
{{- $parts := splitList ":" $address -}}
{{- $refusal := printf "VALIDATION_ERROR kind=cds_address_required: cds.address must be this cluster's CDS as <host>:<port> (got %q), the host a lowercase DNS name or an IPv4 address. Pass `c8s install --cds-address <host:port>`." $address -}}
{{- if ne (len $parts) 2 -}}{{- fail $refusal -}}{{- end -}}
{{- $host := first $parts -}}
{{- if not (regexMatch `^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$` $host) -}}{{- fail $refusal -}}{{- end -}}
{{- $port := last $parts -}}
{{- if or (not (regexMatch `^[1-9][0-9]*$` $port)) (gt (int $port) 65535) -}}{{- fail $refusal -}}{{- end -}}
{{- end -}}

{{- define "c8s.int" -}}
{{- if and (not (kindIs "int" .)) (not (kindIs "float64" .)) (not (regexMatch "^-?[0-9]+$" (toString .))) -}}
{{- fail (printf "expected an integer, got %q" (toString .)) -}}
{{- end -}}
{{- int64 . -}}
{{- end -}}

{{- define "c8s.positiveInt" -}}
{{- if not (regexMatch `^[1-9][0-9]*$` (toString .value)) -}}
{{- fail (printf "%s must be a positive integer, got: %v" .label .value) -}}
{{- end -}}
{{- toString .value -}}
{{- end -}}

{{- define "c8s.commonLabels" -}}
app.kubernetes.io/name: c8s-operator
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: Helm
{{- end -}}

{{/* Host daemons exclude virtual nodes in every required OR term. Empty
     selectors and terms retain their Kubernetes no-match semantics. */}}
{{- define "c8s.hostDaemonAffinity" -}}
{{- $affinity := deepCopy (. | default dict) -}}
{{- $node := get $affinity "nodeAffinity" | default dict -}}
{{- $key := "requiredDuringSchedulingIgnoredDuringExecution" -}}
{{- $exclude := dict "key" "confidential.ai/pod-cvm" "operator" "NotIn" "values" (list "true") -}}
{{- if and (hasKey $node $key) (not (kindIs "invalid" (get $node $key))) -}}
  {{- $required := get $node $key -}}
  {{- $terms := list -}}
  {{- range $term := $required.nodeSelectorTerms -}}
    {{- if or $term.matchExpressions $term.matchFields -}}
      {{- $_ := set $term "matchExpressions" (append ($term.matchExpressions | default list) $exclude) -}}
    {{- end -}}
    {{- $terms = append $terms $term -}}
  {{- end -}}
  {{- if $terms -}}
    {{- $_ := set $required "nodeSelectorTerms" $terms -}}
  {{- end -}}
{{- else -}}
  {{- $_ := set $node $key (dict "nodeSelectorTerms" (list (dict "matchExpressions" (list $exclude)))) -}}
{{- end -}}
{{- $_ := set $affinity "nodeAffinity" $node -}}
{{- toYaml $affinity -}}
{{- end -}}

{{/* Installer and uninstaller share the same host-node eligibility. */}}
{{- define "c8s.nriHostDaemonAffinity" -}}
{{- $expressions := list (dict "key" "kubernetes.io/os" "operator" "In" "values" (list "linux")) -}}
{{- range .Values.nriImagePolicy.nodeAffinity.excludeLabels -}}
  {{- $expressions = append $expressions (dict "key" .key "operator" "NotIn" "values" .values) -}}
{{- end -}}
{{- include "c8s.hostDaemonAffinity" (dict "nodeAffinity" (dict "requiredDuringSchedulingIgnoredDuringExecution" (dict "nodeSelectorTerms" (list (dict "matchExpressions" $expressions))))) -}}
{{- end -}}

{{/* The namespaces the injector leaves alone. The router's is among them
     because the mesh policy designates it for the router role: its pods hold
     platform-role containers the chart renders itself. */}}
{{- define "c8s.webhookExcludedNamespaces" -}}
- key: kubernetes.io/metadata.name
  operator: NotIn
  values:
    - {{ .Release.Namespace }}
    - {{ include "c8s.routerMeshNamespace" . }}
    - kube-system
    - kube-public
    - kube-node-lease
    {{- if not .Values.node.baked }}
    - local-path-storage
    {{- end }}
    {{- range .Values.webhook.extraExcluded }}
    - {{ . }}
    {{- end }}
{{- end }}

{{/* AKS's admissions enforcer honors this opt-out; explicit annotations win. */}}
{{- define "c8s.webhookAnnotations" -}}
{{- $annotations := deepCopy (.Values.webhook.annotations | default dict) -}}
{{- if and (eq (.Values.attestationApi.cvmMode | default "bare-metal") "aks") (not (hasKey $annotations "admissions.enforcer/disabled")) -}}
{{- $_ := set $annotations "admissions.enforcer/disabled" "true" -}}
{{- end -}}
{{- with $annotations }}
annotations:
  {{- toYaml . | nindent 2 }}
{{- end -}}
{{- end -}}

{{/* The reserved identities and ports of the platform roles. These mirror
     pkg/workloadclaims (MeshUID, CredentialsUID, RouterUID, AcmeUID,
     UpstreamUID, Mesh*Port), which the injector builds the containers from and
     the enforcer matches on; a chart test pins them to those constants. */}}
{{- define "c8s.meshUID" -}}1337{{- end -}}
{{- define "c8s.credentialsUID" -}}1338{{- end -}}
{{- define "c8s.routerUID" -}}1339{{- end -}}
{{- define "c8s.acmeUID" -}}1340{{- end -}}
{{- define "c8s.upstreamUID" -}}1341{{- end -}}
{{- define "c8s.meshOutboundPort" -}}15001{{- end -}}
{{- define "c8s.meshInboundPort" -}}15006{{- end -}}
{{- define "c8s.meshHealthPort" -}}15021{{- end -}}

{{/* The credential volume of a member pod: the directory and file names the
     injector fixes (internal/webhook/pod_mutator.go), which the measured base
     pins in the mesh endpoint's argv. A chart-rendered member pod publishes
     and reads the same paths, or its endpoint takes no mesh role. */}}
{{- define "c8s.certDir" -}}/etc/c8s/certs{{- end -}}
{{/* The volume's group, which kubelet adds to every container of the pod, so
     the roles that read a credential can read what the credentials role
     wrote. The injector applies it to a tenant pod (webhook.certVolume). */}}
{{- define "c8s.certFsGroup" -}}{{ include "c8s.int" .Values.webhook.certVolume.fsGroup }}{{- end -}}
{{- define "c8s.certFile" -}}{{ include "c8s.certDir" . }}/tls.crt{{- end -}}
{{- define "c8s.keyFile" -}}{{ include "c8s.certDir" . }}/tls.key{{- end -}}
{{- define "c8s.caFile" -}}{{ include "c8s.certDir" . }}/ca.crt{{- end -}}
