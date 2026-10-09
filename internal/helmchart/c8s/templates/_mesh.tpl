{{/* The pod mesh endpoint. See ../helpers/mesh/README.md. */}}

{{/*
c8s.meshEndpointContainer renders the container the injector builds for a
tenant pod (internal/webhook/pod_mutator.go "meshContainer"): the endpoint that
carries the pod's captured TCP over armTLS with the credentials get-cert
publishes. A chart-rendered member pod gets the same container, because the
measured base grants the mesh role to that argv and that mount alone
(node-guest-image/c8s/image-policy.yaml.in).

Native sidecar, first in the pod's initContainers: the enforcer gates the rest
of the pod on this container's start. Caller nindents into initContainers.
*/}}
{{- define "c8s.meshEndpointContainer" -}}
- name: c8s-mesh
  image: {{ include "c8s-common.image" .Values.armtlsMesh.image }}
  imagePullPolicy: {{ default "IfNotPresent" .Values.armtlsMesh.image.pullPolicy }}
  restartPolicy: Always
  args:
    - --cert-path={{ include "c8s.certFile" . }}
    - --key-path={{ include "c8s.keyFile" . }}
    - --ca-path={{ include "c8s.caFile" . }}
  volumeMounts:
    - name: c8s-certs
      mountPath: {{ include "c8s.certDir" . }}
      readOnly: true
  securityContext:
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
    runAsNonRoot: true
    runAsUser: {{ include "c8s.meshUID" . }}
    runAsGroup: {{ include "c8s.meshUID" . }}
    capabilities:
      drop:
        - ALL
    seccompProfile:
      type: RuntimeDefault
  {{- /* HTTP, never exec: a locked node image denies every runc exec, and an
         exec probe would run another process inside the mesh role. Every
         field is set, so a stored pod still matches what was rendered;
         startup reports initialization, readiness adds usable credentials and
         working listeners. */}}
  startupProbe:
    httpGet:
      path: /startupz
      port: {{ include "c8s.meshHealthPort" . }}
      scheme: HTTP
    periodSeconds: 1
    timeoutSeconds: 1
    successThreshold: 1
    failureThreshold: 60
  readinessProbe:
    httpGet:
      path: /readyz
      port: {{ include "c8s.meshHealthPort" . }}
      scheme: HTTP
    periodSeconds: 5
    timeoutSeconds: 1
    successThreshold: 1
    failureThreshold: 3
{{- end -}}
