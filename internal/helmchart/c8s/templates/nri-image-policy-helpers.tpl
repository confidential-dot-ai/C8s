{{/*
Expand the name of the chart.
*/}}
{{- define "nri-image-policy.name" -}}
nri-image-policy
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "nri-image-policy.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "nri-image-policy.name" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "nri-image-policy.labels" -}}
helm.sh/chart: {{ include "nri-image-policy.name" . }}-0.3.0
{{ include "nri-image-policy.selectorLabels" . }}
app.kubernetes.io/version: ""
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: c8s
{{- end }}

{{/*
Selector labels
*/}}
{{- define "nri-image-policy.selectorLabels" -}}
app: {{ include "nri-image-policy.fullname" . }}
app.kubernetes.io/name: {{ include "nri-image-policy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Install image reference.
*/}}
{{- define "nri-image-policy.image" -}}
{{ include "c8s-common.image" .Values.nriImagePolicy.image }}
{{- end }}

{{/*
Host paths derived from values.
*/}}
{{- define "nri-image-policy.hostPluginPath" -}}
{{ printf "%s/%s" .Values.nriImagePolicy.hostPaths.pluginDir .Values.nriImagePolicy.pluginFilename }}
{{- end }}

{{- define "nri-image-policy.hostConfigPath" -}}
{{ printf "%s/image-policy.yaml" .Values.nriImagePolicy.hostPaths.configDir }}
{{- end }}

{{- define "nri-image-policy.hostHealthSocket" -}}
{{ printf "%s/%s" .Values.nriImagePolicy.hostPaths.runtimeDir .Values.nriImagePolicy.healthSocketName }}
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
  mountPath: /host{{ .Values.nriImagePolicy.hostPaths.cacheDir }}
- name: host-runtime-dir
  mountPath: /host{{ .Values.nriImagePolicy.hostPaths.runtimeDir }}
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
    path: {{ .Values.nriImagePolicy.hostPaths.cacheDir }}
    type: DirectoryOrCreate
- name: host-runtime-dir
  hostPath:
    path: {{ .Values.nriImagePolicy.hostPaths.runtimeDir }}
    type: DirectoryOrCreate
{{- end }}

{{/*
Host mounts for the node-as-CVM pins installer: the baked config it patches and
the runtime dir holding the plugin's health socket. It touches neither the
plugin binary nor containerd's config, so neither is mounted.
*/}}
{{- define "nri-image-policy.pinsVolumeMounts" -}}
- name: host-config-dir
  mountPath: /host{{ .Values.nriImagePolicy.hostPaths.configDir }}
- name: host-runtime-dir
  mountPath: /host{{ .Values.nriImagePolicy.hostPaths.runtimeDir }}
{{- end }}

{{- define "nri-image-policy.pinsVolumes" -}}
- name: host-config-dir
  hostPath:
    path: {{ .Values.nriImagePolicy.hostPaths.configDir }}
    type: DirectoryOrCreate
- name: host-runtime-dir
  hostPath:
    path: {{ .Values.nriImagePolicy.hostPaths.runtimeDir }}
    type: DirectoryOrCreate
{{- end }}

{{/*
Host containerd config directory bind-mounted into the installer.
*/}}
{{- define "nri-image-policy.containerdConfigDir" -}}
{{- if .Values.nriImagePolicy.containerd.configDir -}}
{{ .Values.nriImagePolicy.containerd.configDir }}
{{- else if eq .Values.nriImagePolicy.distro "rke2" -}}
/var/lib/rancher/rke2/agent/etc/containerd
{{- else if eq .Values.nriImagePolicy.distro "k8s" -}}
/etc/containerd
{{- else -}}
{{ fail (printf "nri-image-policy: distro must be \"k8s\" or \"rke2\" (got %q), or set containerd.configDir explicitly" .Values.nriImagePolicy.distro) }}
{{- end -}}
{{- end -}}

{{/*
patch  = splice an in-place sentinel-delimited block into config.toml.
dropin = write a standalone file the installer owns entirely.
*/}}
{{- define "nri-image-policy.containerdConfigMode" -}}
{{- if eq .Values.nriImagePolicy.distro "rke2" -}}
dropin
{{- else if eq .Values.nriImagePolicy.distro "k8s" -}}
patch
{{- else -}}
{{ fail (printf "nri-image-policy: distro must be \"k8s\" or \"rke2\" (got %q)" .Values.nriImagePolicy.distro) }}
{{- end -}}
{{- end -}}

{{/*
Host service restart that makes containerd re-read its config.
*/}}
{{- define "nri-image-policy.restartCommand" -}}
{{- if .Values.nriImagePolicy.containerd.restartCommand -}}
{{ .Values.nriImagePolicy.containerd.restartCommand }}
{{- else if eq .Values.nriImagePolicy.distro "rke2" -}}
{{- /* A server/control-plane node runs rke2-server (which owns containerd); a
       worker node runs rke2-agent. Restart whichever unit is active so the
       install works on a single-node/server cluster too, not just workers. */ -}}
if systemctl is-active --quiet rke2-server; then systemctl restart rke2-server; else systemctl restart rke2-agent; fi
{{- else -}}
systemctl restart containerd
{{- end -}}
{{- end -}}

{{/*
Host containerd socket the plugin connects to.
*/}}
{{- define "nri-image-policy.containerdSocket" -}}
{{- if .Values.nriImagePolicy.containerd.socket -}}
{{ .Values.nriImagePolicy.containerd.socket }}
{{- else if eq .Values.nriImagePolicy.distro "rke2" -}}
/run/k3s/containerd/containerd.sock
{{- else -}}
/run/containerd/containerd.sock
{{- end -}}
{{- end -}}
