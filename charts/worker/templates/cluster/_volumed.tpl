{{/* The node agent that opens encrypted volumes for the pods on its worker
     (docs/volumes.md). The component set admits it as a node service, so the
     launch this renders is the launch the entry pins. It runs its own image,
     which carries cryptsetup. */}}

{{- define "volumed.stateDir" -}}/var/lib/c8s/volumed{{- end -}}
{{- define "volumed.kubeletRoot" -}}/var/lib/kubelet{{- end -}}

{{- define "volumed.args" -}}
{{- list
  (printf "--socket-dir=%s" (include "worker.runtimeDir" .))
  (printf "--state-dir=%s" (include "volumed.stateDir" .))
  (printf "--kubelet-root=%s" (include "volumed.kubeletRoot" .))
  | toJson -}}
{{- end -}}

{{- define "volumed.podSpec" -}}
# Keeps the env names fixed for the allowlist's env match (c8s.componentEnv).
enableServiceLinks: false
# SO_PEERCRED reports a peer's PID in the reader's PID namespace, so a caller
# in another pod resolves to 0 without this.
hostPID: true
# A pod on the pod network waits for a mesh endpoint; this daemon serves a unix socket.
hostNetwork: true
serviceAccountName: {{ include "c8s.volumedName" . }}
automountServiceAccountToken: false
nodeSelector:
  confidential.ai/worker: "true"
tolerations:
  - operator: Exists
    effect: NoExecute
  - operator: Exists
    effect: NoSchedule
containers:
  - name: volumed
    image: {{ include "volumed.image" . }}
    imagePullPolicy: IfNotPresent
    securityContext:
      privileged: true
      # The image is nonroot, and privilege grants a non-root process no capability.
      runAsUser: 0
      runAsGroup: 0
    command: {{ include "c8s.entrypoint" (dict "root" . "valuePath" "volumed.image") }}
    args: {{ include "volumed.args" . }}
    volumeMounts:
      # Bidirectional: the mount is made here and has to reach the workload's
      # pod directory on the node.
      - name: kubelet-root
        mountPath: {{ include "volumed.kubeletRoot" . }}
        mountPropagation: Bidirectional
      - name: state
        mountPath: {{ include "volumed.stateDir" . }}
      - name: dev
        mountPath: /dev
      # /sys whole, not /sys/block: the block entries are symlinks into
      # /sys/devices, and the serial is read through them.
      - name: sys
        mountPath: /sys
        readOnly: true
      - name: cgroup
        mountPath: /sys/fs/cgroup
        readOnly: true
      # INVARIANT: the daemon serves in the inventory's socket directory, the
      # one directory the admission plugin mounts into a cw-pod sidecar.
      - name: inventory-socket-dir
        mountPath: {{ include "worker.runtimeDir" . }}
volumes:
  - name: kubelet-root
    hostPath:
      path: {{ include "volumed.kubeletRoot" . }}
      type: Directory
  # The records outlive the pod, so a replacement keeps the volumes this one
  # opened.
  - name: state
    hostPath:
      path: {{ include "volumed.stateDir" . }}
      type: DirectoryOrCreate
  - name: dev
    hostPath:
      path: /dev
      type: Directory
  - name: sys
    hostPath:
      path: /sys
      type: Directory
  - name: cgroup
    hostPath:
      path: /sys/fs/cgroup
      type: Directory
  - name: inventory-socket-dir
    hostPath:
      path: {{ include "worker.runtimeDir" . }}
      type: Directory
{{- end -}}
