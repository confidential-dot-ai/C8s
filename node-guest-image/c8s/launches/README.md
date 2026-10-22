# Recorded system launches

The node exempts a container from its sandbox policy for more than the host
network only when an entry of its measured base pins the launch: command, args
and mounts exact, environment matched. `systemfloor` derives those entries for
the components RKE2 deploys from its own charts from this capture of a booted
node, and splices them into `../image-policy.yaml.in` between the
`pinned system launches` markers (the NVIDIA device plugin's entry comes from
its baked manifest and `k8s-device-plugin-config.json` instead).

Capture it again when the RKE2 pin or the Cilium chart values change, from a
`C8S_DEV=1` image of the new pins (the serial console has `crictl`):

```sh
kubectl get pods -n kube-system -o json > pods.json   # keep one pod of each pinned DaemonSet
for id in $(crictl ps -a --label io.kubernetes.pod.namespace=kube-system -q); do
  crictl inspect "$id" > "containers/$id.json"        # keep the pinned DaemonSets' containers
done
```

Trim each file to the fields `systemfloor` reads (pod metadata, container names,
images and env; `status.labels`, `status.imageRef`, `info.sandboxID`,
`info.runtimeSpec.process.{args,env}`, `info.runtimeSpec.mounts`), name the
container files after their container, and regenerate (the command is at the
top of `../mkosi.sync`). `k8s-device-plugin-config.json` is
`crane config --platform linux/amd64` of the device plugin image the manifest
pins.
