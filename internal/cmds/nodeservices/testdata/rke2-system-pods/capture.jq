# Trims `kubectl get pods -n kube-system -o json` to what the floor test reads:
# each container's launch and the image digest containerd ran it from.
def launch: {name, image, command, args, env, volumeMounts};
{items: [.items[] | {
  metadata: {name: .metadata.name, namespace: .metadata.namespace},
  spec: {
    nodeName: .spec.nodeName,
    initContainers: ((.spec.initContainers // []) | map(launch)),
    containers: (.spec.containers | map(launch)),
    volumes: .spec.volumes
  },
  status: {containerStatuses: ([.status.initContainerStatuses[]?, .status.containerStatuses[]?] | map({name, imageID}))}
}]}
