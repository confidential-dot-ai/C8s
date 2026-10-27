# Node exec mode

The measured node image starts no new process inside a container that is already
running, for any principal. There is no debug shell on a confidential node, so a
tenant's memory and volume plaintext are not reachable that way; the logs stay
whatever the workload writes.

## What is closed, and where

Two layers, independent of each other: the API server and the runtime.

The API server denies `pods/exec`, `pods/attach`, `pods/portforward` and
`pods/ephemeralcontainers` (`kubectl debug`) for every principal, through a
`ValidatingAdmissionPolicy` the node image bakes. Its expression is a constant
deny, it fails closed, and its binding narrows nothing, so no RBAC grant reaches
those subresources: admission runs after authorization, and no released
credential can delete the policy.

The kubelet's debugging handlers stay **on** in the same image, which is what
keeps logs working: they also back `kubectl logs`, which the `log-reader`
credential exists for, and the kubelet has no logs-only switch. Probes are
unaffected — they go over the container runtime, not the kubelet's HTTP API.

A second baked policy denies the kubelet-proxy subresources — `nodes/proxy`,
`pods/proxy`, `services/proxy` — to every credential the node releases, since
they reach the kubelet's exec endpoint without a `pods/exec` admission check.

That leaves the paths no API-server policy covers — CRI `ExecSync`, an exec
probe, a lifecycle exec hook, a direct call to containerd — and they, like the
proxy paths, end in the same `runc exec`. So the node image puts a measured
wrapper, `c8s-runc`, in front of runc and points containerd's runc handler at
it. In a locked build the wrapper denies the `exec` verb outright and never
reaches the real runtime; every other verb is handed to the real runc unchanged,
by absolute path, and a `restore` is denied in every build, because what it
starts lives in a checkpoint no bundle describes. A denial is written to the log
file runc was told to use, so the pod event names it instead of an empty runtime
error.

Both layers are the measured node image's; the chart installs neither on its
other lanes, which keep the ordinary exec path. A development image
(`C8S_DEV=1`) unwraps the runtime and skips the admission policy, and has its
own launch measurement: exec posture is a property of the image a verifier pins,
not a setting.

## The privilege floor

The same wrapper bounds the privileges of a member pod's containers, because the
node's admission plugin cannot see capabilities, the privileged flag,
`no_new_privs`, or user-namespace mappings
([allowlist-and-capabilities.md](allowlist-and-capabilities.md#host-privilege)).
On `create` and `run` it reads the bundle and refuses the create when a
container the measured mesh policy covers holds more than the floor:

- the runtime's default capabilities less `NET_RAW`, `SETUID` and `SETGID`, in
  all five sets, since each of those defeats the pod's packet rules — and none
  at all for a container on a platform role, one of C8s's own node-side
  identities;
- `no_new_privs` set, so a setuid binary in the image cannot raise what the
  floor just bounded;
- none of the privileged marks: a device cgroup allowing every device, no
  masked or read-only `/proc` paths, a writable `sysfs` or `cgroupfs`;
- its own PID namespace, no user namespace or id mapping — the packet rules
  match the socket's UID in the initial user namespace — and an identity that is
  neither root nor an id reserved for another role.

A measured policy that cannot be read, or that carries no `mesh` policy, denies
the create. The floor is independent of the exec posture above, and leaves the
exempt namespaces and the pod's own sandbox container as the measured policy
found them. Attachability is refused for every container the wrapper creates — a
terminal, and a create carrying the container's standard input — so an attach
session has no way in even there.

## What this means for debugging a workload

Logs are the interface: `kubectl logs` works for every kubeconfig holder, and
`c8s get-kubeconfig --role log-reader` exists for readers who need nothing else
([operator.md](operator.md)).

An exec probe or a lifecycle exec hook cannot pass on such a node, so C8s
renders none. A component that needs a health signal serves it: an HTTP, TCP or
gRPC probe against a port it already listens on, or a small in-process endpoint
when it otherwise listens only on a Unix socket, and it handles SIGTERM instead
of carrying a `preStop` hook.

Container creation is not what this closes: whoever can create a pod can put any
command in its initial process, which the allowlist restricts
([allowlist-and-capabilities.md](allowlist-and-capabilities.md)).