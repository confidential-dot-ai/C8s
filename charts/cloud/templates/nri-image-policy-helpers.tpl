{{- define "nri-image-policy.name" -}}
nri-image-policy
{{- end }}

{{- define "nri-image-policy.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "nri-image-policy.name" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "nri-image-policy.labels" -}}
helm.sh/chart: {{ include "nri-image-policy.name" . }}-0.3.0
{{ include "nri-image-policy.selectorLabels" . }}
app.kubernetes.io/version: ""
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: c8s
{{- end }}

{{- define "nri-image-policy.selectorLabels" -}}
app: {{ include "nri-image-policy.fullname" . }}
app.kubernetes.io/name: {{ include "nri-image-policy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "nri-image-policy.image" -}}
{{ include "c8s-common.image" .Values.nriImagePolicy.image }}
{{- end }}

{{/* The plugin's host directories: runtimeDir holds the sockets of the
     inventory, the attestation-api and volumed, which other components
     mount; cacheDir its exempt-namespace snapshot. */}}
{{- define "nri-image-policy.runtimeDir" -}}/run/nri-image-policy{{- end -}}
{{- define "nri-image-policy.cacheDir" -}}/var/lib/nri-image-policy{{- end -}}

{{/* The name the binary registers at the NRI socket and containerd's
     default_validator requires. */}}
{{- define "nri-image-policy.pluginName" -}}nri-image-policy{{- end -}}

{{/* Upstream containerd's layout. */}}
{{- define "nri-image-policy.containerdConfigDir" -}}/etc/containerd{{- end -}}
{{- define "nri-image-policy.containerdSocket" -}}/run/containerd/containerd.sock{{- end -}}
{{- define "nri-image-policy.restartCommand" -}}systemctl restart containerd{{- end -}}

{{/* The "10-" prefix orders the plugin among the node's NRI plugins. */}}
{{- define "nri-image-policy.hostPluginPath" -}}
{{ printf "%s/10-nri-image-policy" .Values.nriImagePolicy.hostPaths.pluginDir }}
{{- end }}

{{- define "nri-image-policy.hostConfigPath" -}}
{{ printf "%s/image-policy.yaml" .Values.nriImagePolicy.hostPaths.configDir }}
{{- end }}

{{- define "nri-image-policy.hostHealthSocket" -}}
{{ printf "%s/health.sock" (include "nri-image-policy.runtimeDir" .) }}
{{- end }}

{{/*
The CDS this cluster trusts, as the installer mounts it: its address and its
pin, which it copies to the node beside the boot config that names both paths.
*/}}
{{- define "nri-image-policy.cdsPolicyMount" -}}
/mnt/c8s-data/measurements
{{- end }}

{{- define "nri-image-policy.hostCDSAddressPath" -}}
{{ printf "%s/cds-address" .Values.nriImagePolicy.hostPaths.configDir }}
{{- end }}

{{- define "nri-image-policy.hostCDSPinPath" -}}
{{ printf "%s/cds.json" .Values.nriImagePolicy.hostPaths.configDir }}
{{- end }}

{{/*
The installer DaemonSet's long-running container: a readiness endpoint that
follows the host plugin process. The script is shared with its argv-pinned seed
entry (c8s.argvPinnedEntries) so the two cannot drift. It runs under /bin/sh -c
like the entry's other script shapes: `c8s uninstall` takes the entry's one
shape that is not /bin/sh -c as its sweep pause, in CLIs already released too.
*/}}
{{- define "nri-image-policy.pluginReadyPort" -}}
8080
{{- end }}

{{- define "nri-image-policy.pluginReadyScript" -}}
exec /usr/local/bin/c8s nri-image-policy plugin-ready --plugin-path={{ include "nri-image-policy.hostPluginPath" . | squote }} --addr=:{{ include "nri-image-policy.pluginReadyPort" . }}
{{- end }}

{{- define "nri-image-policy.resources" -}}
requests:
  cpu: 50m
  memory: 32Mi
limits:
  cpu: 200m
  memory: 256Mi
{{- end }}

{{/*
Shared hostPath mounts and volumes used by installer DaemonSets and the
uninstall hook.
*/}}
{{- define "nri-image-policy.hostVolumeMounts" -}}
- name: host-plugin-dir
  mountPath: /host{{ .Values.nriImagePolicy.hostPaths.pluginDir }}
- name: host-config-dir
  mountPath: /host{{ .Values.nriImagePolicy.hostPaths.configDir }}
- name: host-containerd-config
  mountPath: /host{{ include "nri-image-policy.containerdConfigDir" . }}
- name: host-cache-dir
  mountPath: /host{{ include "nri-image-policy.cacheDir" . }}
- name: host-runtime-dir
  mountPath: /host{{ include "nri-image-policy.runtimeDir" . }}
- name: cds-policy
  mountPath: {{ include "nri-image-policy.cdsPolicyMount" . }}
  readOnly: true
{{- end }}

{{- define "nri-image-policy.hostVolumes" -}}
- name: host-plugin-dir
  hostPath:
    path: {{ .Values.nriImagePolicy.hostPaths.pluginDir }}
    type: DirectoryOrCreate
- name: host-config-dir
  hostPath:
    path: {{ .Values.nriImagePolicy.hostPaths.configDir }}
    type: DirectoryOrCreate
- name: host-containerd-config
  hostPath:
    path: {{ include "nri-image-policy.containerdConfigDir" . }}
    type: Directory
- name: host-cache-dir
  hostPath:
    path: {{ include "nri-image-policy.cacheDir" . }}
    type: DirectoryOrCreate
- name: host-runtime-dir
  hostPath:
    path: {{ include "nri-image-policy.runtimeDir" . }}
    type: DirectoryOrCreate
- name: cds-policy
  projected:
    sources:
      - configMap:
          name: {{ include "c8s.fullname" . }}-measurements
{{- end }}
