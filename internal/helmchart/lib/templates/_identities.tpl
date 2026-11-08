{{/* Reserved identities and credential paths. See ../helpers/common/README.md. */}}

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

{{/* The operator Service port the API server dials the webhooks on. The
     Service and both webhook configurations name the same port. */}}
{{- define "c8s.webhookServicePort" -}}443{{- end -}}

{{/* The fixed namespace whose pods serve the router's own ports, as the
     enforcer compiles it (pkg/workloadclaims.RouterNamespace). Not the release
     namespace, whose pods the mesh policy exempts. */}}
{{- define "c8s.routerMeshNamespace" -}}
c8s-router
{{- end -}}

{{/* The credential volume of a member pod: the directory and file names the
     injector fixes (internal/webhook/pod_mutator.go), which the measured base
     pins in the mesh endpoint's argv. A chart-rendered member pod publishes
     and reads the same paths, or its endpoint takes no mesh role. */}}
{{- define "c8s.certDir" -}}/etc/c8s/certs{{- end -}}
{{/* The volume's group, which kubelet adds to every container of the pod, so
     the roles that read a credential can read what the credentials role
     wrote. The injector applies it to a tenant pod (--cert-fs-group). */}}
{{- /* Takes the fsGroup value. */ -}}
{{- define "c8s.certFsGroup" -}}{{ include "c8s.int" . }}{{- end -}}
{{- define "c8s.certFile" -}}{{ include "c8s.certDir" . }}/tls.crt{{- end -}}
{{- define "c8s.keyFile" -}}{{ include "c8s.certDir" . }}/tls.key{{- end -}}
{{- define "c8s.caFile" -}}{{ include "c8s.certDir" . }}/ca.crt{{- end -}}
