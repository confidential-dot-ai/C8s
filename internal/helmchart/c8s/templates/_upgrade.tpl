{{/* Fails an upgrade that changes CDS's own shape before that shape is
     published. CDS is recreated, not rolled, so the running enforcers must
     already admit the new CDS through the old one: otherwise the old CDS
     stops and the new one never starts. Takes live (the running Deployment's
     shape, "" when unknown), want (the rendered shape), entry (the seed entry
     admitting it) and published (cds.publishedShape). */ -}}
{{- define "c8s.cdsShapeGuard" -}}
{{- if and .live .want (ne .live .want) (ne .published .want) -}}
{{- fail (printf "this upgrade changes the CDS image, command line or mounts, and the running enforcers do not admit the new CDS yet. To proceed, publish entry %s from the new release's seed through the running CDS (c8s allowlist apply, repeated until c8s allowlist list reports a version above every allowlist_version the nodes' image policy plugins reported on /healthz before), wait until every plugin reports a version at or above it, then rerun with --set cds.publishedShape=%s" (default .want .entry) .want) -}}
{{- end -}}
{{- end -}}
