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

{{/* The inventory socket, which the plugin serves (workloadclaims.SocketName). */}}
{{- define "nri-image-policy.workloadClaimsSocket" -}}
{{ printf "%s/workload-claims.sock" (include "nri-image-policy.runtimeDir" .) }}
{{- end -}}

{{/* The namespaces of the pods a node runs for the platform, which are up
     before any enforcer is. */}}
{{- define "nri-image-policy.platformNamespaces" -}}
{{- list .Release.Namespace "kube-system" "local-path-storage" | toJson -}}
{{- end -}}

{{/* The mesh gate's exempt namespaces, as a YAML list: the platform
     namespaces plus every namespace image admission exempts, which the plugin
     requires to be a superset of policy.exempt_namespaces. */}}
{{- define "nri-image-policy.meshExemptNamespaces" -}}
{{- $root := . -}}
{{- $platform := include "nri-image-policy.platformNamespaces" $root | fromJsonArray -}}
{{- $exempt := concat $platform ($root.Values.nriImagePolicy.policy.exemptNamespaces | default list) | uniq -}}
{{- $router := include "c8s.routerMeshNamespace" $root -}}
{{- if has $router $exempt -}}
{{- fail (printf "the mesh gate cannot exempt %s, whose pods serve the router's ports and are members: the plugin refuses such a config at start" $router) -}}
{{- end -}}
{{- $entries := list -}}
{{- range $ns := $exempt -}}
{{- $entries = append $entries (printf "- %s" ($ns | quote)) -}}
{{- end -}}
{{- join "\n" $entries -}}
{{- end -}}

{{/* The name the binary registers at the NRI socket and containerd's
     default_validator requires. */}}
{{- define "nri-image-policy.pluginName" -}}nri-image-policy{{- end -}}

{{/* Upstream containerd's layout. */}}
{{- define "nri-image-policy.containerdConfigDir" -}}/etc/containerd{{- end -}}
{{- define "nri-image-policy.containerdSocket" -}}/run/containerd/containerd.sock{{- end -}}
{{- define "nri-image-policy.restartCommand" -}}systemctl restart containerd{{- end -}}

{{/* The host's syslog socket: the plugin logs to the host journal through it. */}}
{{- define "nri-image-policy.syslogSocket" -}}/dev/log{{- end -}}

{{/* The sweep `c8s uninstall` replays: the shared containerd-config and
     plugin-removal helpers, then the sweep's own steps (internal/helmchart
     hostSweepScripts joins the same files in the same order). */}}
{{- define "nri-image-policy.hostSweepScript" -}}
{{ .Files.Get "files/scripts/nri-containerd-config.sh" }}
{{ .Files.Get "files/scripts/nri-plugin-removal.sh" }}
{{ .Files.Get "files/scripts/host-sweep.sh" }}
{{- end -}}

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

{{/* The installer DaemonSet's hostPath mounts and volumes. */}}
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
