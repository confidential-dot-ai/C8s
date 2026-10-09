{{/* Certificates helpers. See ../helpers/certificates/README.md. */}}

{{- define "c8s.getCertContainers" -}}
{{- $root := .root -}}
- name: c8s-cert
  image: {{ include "c8s.image" $root }}
  imagePullPolicy: {{ $root.Values.image.pullPolicy }}
  restartPolicy: Always
  args:
    - get-cert
    - --cds-url={{ include "c8s.cdsURL" $root }}
    - --attestation-api-url={{ include "c8s.attestationApiURL" $root }}
    {{- if .sanFile }}
    - --san-file={{ .sanFile }}
    {{- else }}
    - --san={{ .san }}
    {{- end }}
    - --cert-path={{ .certOut }}
    - --key-path={{ .keyOut }}
    - --ca-path={{ .caOut }}
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
    - name: {{ .volume }}
      mountPath: {{ .mountPath }}
    {{- with .extraMounts }}
    {{- . | nindent 4 }}
    {{- end }}
  # The workload is gated on the initial cert by the c8s-cert-wait init
  # container below, not a startupProbe here.
  securityContext:
    {{- include "c8s.getCertSecurityContext" . | nindent 4 }}
# c8s-cert-wait gates the workload on the initial cert without an exec probe.
# A plain (run-once) init container blocks on the cert file, and normal
# init-completion ordering holds the workload until the attested cert exists —
# fail-closed.
# The `/c8s` path is the binary location from cmd/c8s/Dockerfile; command
# bypasses the ENTRYPOINT so the full path must match.
- name: c8s-cert-wait
  image: {{ include "c8s.image" $root }}
  imagePullPolicy: {{ $root.Values.image.pullPolicy }}
  command:
    - /c8s
    - probe-file
    - --wait
    - --timeout=3m
    - {{ .certOut }}
  volumeMounts:
    - name: {{ .volume }}
      mountPath: {{ .mountPath }}
  securityContext:
    {{- include "c8s.getCertSecurityContext" . | nindent 4 }}
{{- end -}}

{{- define "c8s.getCertSecurityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
runAsNonRoot: {{ .runAsNonRoot }}
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
