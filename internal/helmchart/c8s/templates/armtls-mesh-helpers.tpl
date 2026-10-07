{{/*
Expand the name of the chart.
*/}}
{{- define "armtls-mesh.name" -}}
armtls-mesh
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "armtls-mesh.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "armtls-mesh.name" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "armtls-mesh.labels" -}}
helm.sh/chart: {{ include "armtls-mesh.name" . }}-0.1.0
{{ include "armtls-mesh.selectorLabels" . }}
app.kubernetes.io/version: ""
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: c8s
{{- end }}

{{/*
Selector labels
*/}}
{{- define "armtls-mesh.selectorLabels" -}}
app: {{ include "armtls-mesh.fullname" . }}
app.kubernetes.io/name: {{ include "armtls-mesh.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Image reference
*/}}
{{- define "armtls-mesh.image" -}}
{{ include "c8s-common.image" .Values.armtlsMesh.image }}
{{- end }}

{{/*
armtls-mesh.durationSeconds — parse a Go-style duration into integer seconds.
Supports the single-unit forms (Ns, Nm, Nh) that fit chart-bound arithmetic;
compound forms ("1m30s") are intentionally rejected so the bound math stays
exact instead of silently truncating via sprig's lenient int parsing.
*/}}
{{- define "armtls-mesh.durationSeconds" -}}
{{- $d := . -}}
{{- $unit := "" -}}
{{- $num := "" -}}
{{- if hasSuffix "h" $d -}}
{{- $unit = "h" -}}
{{- $num = trimSuffix "h" $d -}}
{{- else if hasSuffix "m" $d -}}
{{- $unit = "m" -}}
{{- $num = trimSuffix "m" $d -}}
{{- else if hasSuffix "s" $d -}}
{{- $unit = "s" -}}
{{- $num = trimSuffix "s" $d -}}
{{- else -}}
{{- fail (printf "duration %q must end with h, m, or s (single unit only)" $d) -}}
{{- end -}}
{{- if not (mustRegexMatch "^[0-9]+$" $num) -}}
{{- fail (printf "duration %q must be a positive integer followed by a single unit (h, m, or s)" $d) -}}
{{- end -}}
{{- $n := $num | int -}}
{{- if eq $unit "h" -}}{{- mul 3600 $n -}}
{{- else if eq $unit "m" -}}{{- mul 60 $n -}}
{{- else -}}{{- $n -}}{{- end -}}
{{- end }}
