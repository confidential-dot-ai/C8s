{{/* Fails an upgrade that changes CDS's own shape before that shape is
     published. CDS is recreated, not rolled, so the running enforcers must
     already admit the new CDS through the old one: otherwise the old CDS
     stops and the new one never starts. Takes live (c8s.cdsLiveShape), want
     (the rendered shape) and published (cds.publishedShape). */ -}}
{{- define "c8s.cdsShapeGuard" -}}
{{- if and .want (ne .live "none") (ne .live .want) (ne .published .want) -}}
{{- $publish := printf "publish entry %s from the new release's seed through the running CDS (c8s allowlist apply), wait until every node's image policy plugin reports an allowlist_version on /healthz at or above the one c8s allowlist list reports, then rerun with --set cds.publishedShape=%s" .want .want -}}
{{- if .live -}}
{{- fail (printf "this upgrade changes the CDS image, command line or mounts, and the running enforcers do not admit the new CDS yet. To proceed, %s" $publish) -}}
{{- else -}}
{{- fail (printf "cannot tell which CDS runs: the live CDS Deployment has no confidential.ai/cds-shape annotation, or this render cannot look it up (helm template, a GitOps controller). If no CDS runs yet, set cds.liveShape=none. Otherwise, %s" $publish) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* The CDS shape running now: the live Deployment's
     confidential.ai/cds-shape annotation, "none" when no CDS Deployment
     exists, else cds.liveShape ("" when unset, which the guard treats as
     unknown). lookup answers nothing outside a cluster, so a render that
     cannot read kube-system cannot tell a first install from an upgrade. A
     baked node renders the chart before any CDS exists. */ -}}
{{- define "c8s.cdsLiveShape" -}}
{{- $live := "" -}}
{{- if .Values.node.baked -}}
{{- $live = "none" -}}
{{- else if lookup "v1" "Namespace" "" "kube-system" -}}
{{- with lookup "apps/v1" "Deployment" .Release.Namespace (include "c8s.cdsName" .) -}}
{{- $live = dig "metadata" "annotations" "confidential.ai/cds-shape" "" . -}}
{{- else -}}
{{- $live = "none" -}}
{{- end -}}
{{- end -}}
{{- default (default "" .Values.cds.liveShape) $live -}}
{{- end -}}
