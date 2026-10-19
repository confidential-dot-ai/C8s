{{/* Fails an upgrade that changes CDS's own shape before that shape is
     published. CDS is recreated, not rolled, so the running enforcers must
     already admit the new CDS through the old one: otherwise the old CDS
     stops and the new one never starts. Takes live (the running Deployment's
     shape, "" when unknown), want (the rendered shape), entry (the seed entry
     admitting it) and published (cds.publishedShape). */ -}}
{{- define "c8s.cdsShapeGuard" -}}
{{- if and .live .want (ne .live .want) (ne .published .want) -}}
{{- $publish := "with c8s allowlist apply, signed with an operator key. Repeat the apply" -}}
{{- if and .entry (ne .entry .want) -}}
{{- $publish = "with c8s allowlist apply, signed with an operator key; when a served entry shadows the override, apply refuses it, so publish it in one c8s allowlist upload that also retires the generated entries it overrides, after which pods running them, this CDS included when the override names its digest, cannot restart until the upgrade. Repeat the write" -}}
{{- end -}}
{{- fail (printf "this upgrade changes the CDS image, command line or mounts, and the running enforcers do not admit the new CDS yet. To proceed, publish entry %s from the new release's seed through the running CDS %s until c8s allowlist list reports a version above every allowlist_version the nodes' image policy plugins reported on /healthz before, or restart the image policy plugin (containerd) on each node that reports more. Wait until every plugin reports a version at or above it, then rerun with --set cds.publishedShape=%s (docs/allowlist-and-capabilities.md)" (default .want .entry) $publish .want) -}}
{{- end -}}
{{- end -}}
