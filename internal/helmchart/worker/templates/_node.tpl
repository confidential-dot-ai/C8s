{{/* The worker image's node services the router's containers reach: the
     attestation-api and the admission inventory serve sockets under one
     runtime directory, which the pod mounts at both paths their clients
     compile. */}}
{{- define "worker.runtimeDir" -}}/run/nri-image-policy{{- end -}}
{{- define "worker.inventoryDir" -}}/run/c8s/workload-claims{{- end -}}

{{/* The socket the node serves the attestation-api on, under the directory
     the container reads it from. Takes dir. */}}
{{- define "worker.attestationApiURL" -}}unix://{{ .dir }}/attestation-api.sock{{- end -}}

{{/* workloadclaims.InventorySocketGID, the group of the node's sockets. */}}
{{- define "worker.inventorySocketGID" -}}65532{{- end -}}
