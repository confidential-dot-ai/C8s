# Node exec mode

The measured node image starts no new process inside a container that is
already running, for any principal, other than a command its measured policy
grants ([below](#granted-execs)).

Guarantee: [No privileged way in](guarantees.md#no-privileged-way-in).

There is no debug shell on a confidential node, so a tenant's memory and volume
plaintext are not reachable that way.

## What is closed, and where

Two layers, independent of each other: the kubelet and the runtime.

The kubelet serves no debugging handler. Its measured configuration turns the
debugging, system-log, profiling and debug-flag handlers and the read-only port
off, so an `exec`, `attach`, `port-forward`, log or checkpoint request reaches
no endpoint, whatever the control plane authorizes
([launch-configuration.md](launch-configuration.md#staging-a-worker-document)).
What it still serves — `/pods`, `/stats`, `/metrics` — takes bearer tokens the
API server reviews. Probes are unaffected: they go over the container runtime,
not the kubelet's HTTP API. The control plane sits outside the node's TEE, so
this image's own configuration is what closes those paths.

That leaves the paths no kubelet handler covers — CRI `ExecSync`, an exec
probe, a lifecycle exec hook, a direct call to containerd — and they all end in
the same `runc exec`. So the node image puts a measured wrapper, `c8s-runc`, in
front of runc and points containerd's runc handler at it. The image is built in
locked exec mode: the wrapper denies the `exec` verb without reaching the real
runtime, except for a granted command ([below](#granted-execs)); every other
verb is handed to the real runc unchanged, by absolute path, and a `restore` is denied, because what it starts lives in a checkpoint no
bundle describes. A denial is written to the log file runc was told to use, so
the pod event names it instead of an empty runtime error.

Both layers are the measured node image's; the chart installs neither on its
other lanes, which keep the ordinary exec path.

## The privilege floor

The same wrapper bounds the privileges of a member pod's containers, because the
node's admission plugin cannot see the privileged flag, `no_new_privs`, or
user-namespace mappings, and the start check where it reads capabilities is one
the runtime skips when the plugin does not answer
([allowlist-and-capabilities.md](allowlist-and-capabilities.md#host-privilege)).
On `create` and `run` it reads the bundle and refuses the create when a
container the measured mesh policy covers holds more than the floor:

- in none of the five capability sets, a capability outside the node's default
  set that admission did not grant the container — and no capability at all for
  a container on a platform role, one of C8s's own node-side identities;
- `no_new_privs` set, so a setuid binary in the image cannot raise its
  capabilities;
- none of the privileged marks: a device cgroup allowing every device, no
  masked or read-only `/proc` paths, a writable `sysfs` or `cgroupfs`;
- its own PID namespace, no user namespace or id mapping — the packet rules
  match the socket's UID in the initial user namespace — and an identity that is
  neither root nor an id reserved for another role;
- a working directory that is not at or below a data or host mount (a
  ConfigMap, Secret, projected or downward API volume, a PVC or CSI volume, or a
  host path), resolved through the image's symlinks; an emptyDir, including the
  pod's shared memory, is allowed, since only the pod's own containers write it.
  The allowlist pins the command line, and an interpreter looks up its first
  module in the working directory.

The bundle names a container's image, not the digest admission matched, so the
plugin records what an entry declares for each launch it clears: the
capabilities beyond the node's default set, under `/run/nri-image-policy-caps`,
removed with the container. It writes them at the check whose failure fails the
create, so a container the plugin's start check never judges — the check the
runtime skips when the plugin does not answer — holds the default set alone.

A measured policy that cannot be read, or that carries no `mesh` policy, denies
the create. The floor is independent of the exec posture above, and leaves the
exempt namespaces, the pod's own sandbox container and a static pod as the
measured policy found them. Attachability is refused for every container the
wrapper creates — a terminal, and a create carrying the container's standard
input — so an attach session has no way in even there.

A static pod is known by the kubelet's `kubernetes.io/config.source: file`,
which reaches the bundle only where the node's containerd passes it through
(`pod_annotations`), as a worker's does. Before the create, the node's
admission plugin refuses any NRI plugin's edit of that annotation and, on a
worker, a static pod whose launch no base entry pins.

## What this means for debugging a workload

A worker's kubelet answers no log request, so `kubectl logs` reads nothing
there, and an exec probe or a lifecycle exec hook cannot pass, granted
commands aside, so C8s renders none. A component that needs a health signal serves it: an HTTP, TCP or gRPC
probe against a port it already listens on, or a small in-process endpoint when
it otherwise listens only on a Unix socket, and it handles SIGTERM instead of
carrying a `preStop` hook.

## Granted execs

A container entry in the measured base allowlist may list `execs`: the exact
commands the wrapper lets through into a running container of those bytes. The
field is YAML-only, like `role`, so only a measured boot config grants one and
no served document can
([allowlist-and-capabilities.md](allowlist-and-capabilities.md)). An entry
grants them only when it pins the command, the args and the mounts, and never
in a pod the mesh gates cover: no new process starts in a member pod. The
worker image's floor lists none.

The bundle the wrapper reads names a container's image, not the digest
admission matched, so the admission plugin records what it granted: when it
starts a container whose launch the base grants execs, it writes the container
ID and the commands to `/run/nri-image-policy-exec`, a directory only the
plugin writes, and removes the record with the container. `c8s-runc` lets an
`exec` reach the real runtime only when:

- it comes in the form containerd's shim sends: `--process`, with only
  `--detach` and `--pid-file` beside it, and the container ID last;
- the plugin recorded a grant for that container, and the command is exactly
  one it names;
- the process is the container's own process from its bundle, with only the
  command replaced and no terminal, which is what containerd builds for an
  exec probe.

The wrapper hands the real runtime a private copy of the process it checked,
not the caller's file. Whoever triggers such an exec can run only a granted
command. Every other exec is denied.

A denial names its reason after the locked-mode message, in the pod event and
the runtime log. A denied probe reaches the kubelet as a runtime error, which it
discards rather than counting as a failure, so a probe command the wrapper
denies leaves the pod un-Ready without restarting it.

Container creation is not what this closes: whoever can create a pod can put any
command in its initial process, which the allowlist restricts
([allowlist-and-capabilities.md](allowlist-and-capabilities.md)).
