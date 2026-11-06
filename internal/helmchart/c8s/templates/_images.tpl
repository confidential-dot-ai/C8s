{{/* Images helpers. See ../helpers/images/README.md. */}}

{{- define "c8s.image" -}}
{{- if .Values.image.digest -}}
{{ .Values.image.repository }}@{{ .Values.image.digest }}
{{- else if .Values.image.tag -}}
{{ .Values.image.repository }}:{{ .Values.image.tag }}
{{- else -}}
{{ fail "image.tag or image.digest must be set" }}
{{- end -}}
{{- end -}}

{{- define "c8s.attestationApiImage" -}}
{{- if .Values.attestationApi.image.digest -}}
{{ .Values.attestationApi.image.repository }}@{{ .Values.attestationApi.image.digest }}
{{- else if .Values.attestationApi.image.tag -}}
{{ .Values.attestationApi.image.repository }}:{{ .Values.attestationApi.image.tag }}
{{- else -}}
{{ fail "attestationApi.image.tag or attestationApi.image.digest must be set" }}
{{- end -}}
{{- end -}}

{{- define "c8s.imagePullSecrets" -}}
{{- $secrets := .local | default .root.Values.imagePullSecrets | default list -}}
{{- with .root.Values.imagePullSecret -}}
{{- $secrets = uniq (append $secrets (dict "name" .)) -}}
{{- end -}}
{{- with $secrets }}
imagePullSecrets:
{{ toYaml . }}
{{- end -}}
{{- end -}}

{{- define "c8s.serviceAccountImagePullSecrets" -}}
{{- include "c8s.imagePullSecrets" (dict "root" . "local" .Values.serviceAccount.imagePullSecrets) -}}
{{- end -}}

{{- define "volumed.image" -}}
{{ include "c8s-common.image" .Values.volumed.image }}
{{- end -}}

{{- define "c8s-common.image" -}}
{{- $img := . -}}
{{- if $img.digest -}}
{{ $img.repository }}@{{ $img.digest }}
{{- else -}}
{{ $img.repository }}:{{ required (printf "image.tag or image.digest is required for %s" $img.repository) $img.tag }}
{{- end -}}
{{- end }}
