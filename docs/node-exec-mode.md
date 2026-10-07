# Node exec mode

The measured node image (`node-guest-image/c8s`) denies starting a new process
inside a container that is already running. This page describes what enforces
that, what it costs, and what to do when a component needs a health check.

The kubelet's debugging handlers are off in the same image
(`enable-debugging-handlers=false`), which closes `kubectl exec`, `attach`,
`port-forward` and `logs` over the kubelet's HTTP API. That setting does not
cover CRI `ExecSync`, which is how exec probes and lifecycle exec hooks run,
nor a direct call to containerd. The runtime wrapper below covers all of them,
because every one of those paths ends in the same `runc exec`.

## The wrapper

`internal/cmds/c8srunc` is a dispatcher in front of runc:

```text
if build == locked && subcommand == exec:
    exit non-zero, never reach runc
else:
    execve the real runc with the original argv, environment and file descriptors
```

It parses runc's global options — `--debug`, `--log`, `--log-format`, `--root`,
`--systemd-cgroup`, `--rootless`, in every spelling Go's flag package accepts,
including after a `--` — only to find the subcommand. An option it does not
recognise is a denial, not a guess: a token modelled wrongly shifts which
argument the subcommand is. It has no allowlist, reads no configuration, and
takes its posture from a build-time constant, so nothing on a running node can
change it.

A denial also lands in the file named by `--log`, in the format `--log-format`
asks for. containerd builds the error it returns to the kubelet from that file,
so the pod event names the denial instead of an empty runtime error.

The real runtime is RKE2's own runc at `/var/lib/rancher/rke2/bin/runc`, named
by absolute path. RKE2 extracts it there from the measured airgap bundle on
first start; the wrapper never resolves `runc` through `PATH`.

## Wiring in the image

The wrapper ships only in the RKE2 node image. The chart installs nothing of
it on kubeadm or hosted clusters, which keep the ordinary exec path.

`mkosi.sync` installs the wrapper at `/usr/local/bin/c8s-runc` — the same
measured binary the NRI plugin is, under the name `cmd/c8s/main.go` dispatches
on — and the baked drop-in
`config-v3.toml.d/10-c8s-runc.toml` points the runc handler's containerd
`BinaryName` at it. The setting is a drop-in because the profile bakes no
`config-v3.toml.tmpl`: RKE2's base template already defines that table and
imports the drop-in directory, and containerd's TOML parser rejects a
duplicate key. containerd merges each import over the main config key by key.

`C8S_DEV=1` renders `60-dev-runc.toml` over it, restoring the unwrapped
runtime. The dev image already ships a serial root shell and the kubelet
debugging handlers, and it has its own launch measurement — exec posture is a
property of the image, not a setting.

## The build gate

`node-guest-image/c8s/containerdcheck` renders RKE2's base template the way
RKE2 does, merges the drop-ins containerd imports, and asserts that every
enabled ordinary-pod handler runs the wrapper. It fails on an empty
`BinaryName` (which means `PATH` runc), an alternate runc, a later drop-in that
unwraps the handler, an unaudited shim, and a `default_runtime_name` that is
not one of the wrapped handlers.

RKE2 adds a handler for each runtime binary it finds on `PATH` — `crun`, the
nvidia runtimes, the wasm shims (k3s `pkg/agent/containerd/runtimes.go`). None
would be wrapped, so `.github/scripts/node-guest-image-invariants.sh` fails if
the profile bakes any of them, and the CI job runs `containerdcheck` a second
time with `-extra-runtime` to prove the check still catches one.

RKE2's base template is vendored at
`node-guest-image/c8s/containerdcheck/rke2-base-v3.toml.tmpl`. Its header
records the RKE2 version it came from, and the invariants gate compares that to
`mkosi.sync`'s `RKE2_VERSION`: a pin bump must re-vendor.

## Writing a component that runs on such a node

A C8s-owned exec probe or lifecycle exec hook cannot pass on a locked node, so
the chart renders none and
`TestChartRendersNoExecProbes` keeps it that way. Use, in order of
preference:

1. An HTTP, TCP or gRPC probe against a port the component already serves.
2. A minimal in-process health endpoint, when the service otherwise listens
   only on a Unix socket. `attest-proxy --health-addr` serves `GET /healthz` by
   making the same round-trip over its own socket that its exec probe used to
   make; `ratls-mesh iptables-sync --ready-addr` and `acme --ready-port` do the
   same for their readiness signals.
3. SIGTERM handling instead of a `preStop` hook. The mesh's cleanup sidecar
   runs `ratls-mesh iptables-cleanup --on-shutdown`, which idles until SIGTERM
   and then cleans up; native sidecars stop in reverse init order, so it still
   runs after the proxy drains.

## Known limits

- The wrapper covers post-start exec, not container creation. Whoever can
  create a pod can put the command in its initial process; the image policy
  plugin (`internal/cmds/nri-image-policy`) is what restricts that.
- `runc checkpoint` and `restore` are not aliases of `exec` and pass through.
- RKE2's runc stays reachable by name on containerd's `PATH`, because RKE2 puts
  its own data directory there. No enabled handler resolves it, but the wrapper
  is not the only path to that binary for a process already running as root on
  the node.
- Under the immutable root the wrapper itself is on the read-only verity image
  (`/usr/local/bin`, covered by no `state.d` entry). The containerd
  configuration that names it and RKE2's extracted runc both live under `/var`,
  which is a writable overlay backed by the encrypted scratch disk: they are
  reconstructed at each boot from measured inputs — the baked template and
  drop-ins, and the baked airgap bundle — rather than read from the verity
  image directly.
