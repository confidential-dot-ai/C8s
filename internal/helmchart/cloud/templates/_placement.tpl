{{/* Host daemon placement. See ../helpers/placement/README.md. */}}

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
{{- $linux := dict "key" "kubernetes.io/os" "operator" "In" "values" (list "linux") -}}
{{- include "c8s.hostDaemonAffinity" (dict "nodeAffinity" (dict "requiredDuringSchedulingIgnoredDuringExecution" (dict "nodeSelectorTerms" (list (dict "matchExpressions" (list $linux)))))) -}}
{{- end -}}
