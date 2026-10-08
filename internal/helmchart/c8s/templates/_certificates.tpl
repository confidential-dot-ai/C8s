{{/* Certificates helpers. See ../helpers/certificates/README.md. */}}

{{- define "c8s.getCertContainers" -}}
{{- $root := .root -}}
{{- $certOut := include "c8s.certFile" $root -}}
{{- $security := include "c8s.getCertSecurityContext" (dict
  "runAsUser" (include "c8s.credentialsUID" $root)
  "runAsGroup" (include "c8s.credentialsUID" $root)
) -}}
- name: c8s-cert
  image: {{ include "c8s.image" $root }}
  imagePullPolicy: {{ $root.Values.image.pullPolicy }}
  restartPolicy: Always
  {{- /* This container holds the credentials role, so the node hands it the
         one CDS its pod may reach and refuses an argument naming another
         (cmdsutil.ResolveCDSEndpoint). */}}
  args:
    - get-cert
    - --attestation-api-url={{ .attestationApiURL }}
    {{- if .sanFile }}
    - --san-file={{ .sanFile }}
    {{- else }}
    - --san={{ .san }}
    {{- end }}
    - --cert-path={{ $certOut }}
    - --key-path={{ include "c8s.keyFile" $root }}
    - --ca-path={{ include "c8s.caFile" $root }}
    # Retry CDS in-process during a roll instead of exiting into kubelet
    # CrashLoopBackOff; still fails closed once the timeout elapses.
    - --initial-retry-timeout={{ $root.Values.certProvisioning.initialRetryTimeout }}
    - --renew-interval={{ .renewInterval }}
    - --continue-on-initial-error
    {{- range .extraArgs }}
    - {{ . }}
    {{- end }}
  {{- with (include "c8s.attestationApiHostIPEnv" $root) }}
  # cvmMode=bare-metal: expands $(HOST_IP) in --attestation-api-url to the node IP so
  # this pod-netns sidecar reaches the node-baked host attestation-api.
  env:
    {{- . | nindent 4 }}
  {{- end }}
  volumeMounts:
    - name: tls-certs
      mountPath: {{ include "c8s.certDir" $root }}
    {{- with .extraMounts }}
    {{- . | nindent 4 }}
    {{- end }}
  # The workload is gated on the initial cert by the c8s-cert-wait init
  # container below, not a startupProbe here.
  securityContext:
    {{- $security | nindent 4 }}
# c8s-cert-wait gates the workload on the initial cert without an exec probe.
# A plain (run-once) init container blocks on the cert file, and normal
# init-completion ordering holds the workload until the attested cert exists —
# fail-closed.
# The `/c8s` path is the binary location from cmd/c8s/Dockerfile; command
# bypasses the ENTRYPOINT so the full path must match.
#
# INVARIANT: this argv is the one the injector builds (internal/webhook
# "certWaitContainer"), which the measured base pins for the credentials role.
- name: c8s-cert-wait
  image: {{ include "c8s.image" $root }}
  imagePullPolicy: {{ $root.Values.image.pullPolicy }}
  command:
    - /c8s
    - probe-file
    - --wait
    - --timeout=3m0s
    - {{ $certOut }}
  volumeMounts:
    - name: tls-certs
      mountPath: {{ include "c8s.certDir" $root }}
  securityContext:
    {{- $security | nindent 4 }}
{{- end -}}

{{- define "c8s.getCertSecurityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
runAsNonRoot: true
runAsUser: {{ include "c8s.int" .runAsUser }}
runAsGroup: {{ include "c8s.int" .runAsGroup }}
capabilities:
  drop:
    - ALL
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{- define "c8s.cdsDnsSanPattern" -}}
^[a-z0-9-]+[.][a-z0-9-]+[.]svc$
{{- end -}}
