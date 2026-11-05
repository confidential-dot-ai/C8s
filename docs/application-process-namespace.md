# Application process namespaces

Selected application containers can share one Linux PID namespace in a pod.
C8s support containers and applications without this permission keep private
PID namespaces. Keep Kubernetes `shareProcessNamespace` false or unset.

Operator-supplied application containers must not be able to read C8s
authentication credentials, including through another process's `/proc` view.
Process sharing between applications is permitted. The signed workload policy
still controls application launches, capabilities, and application secret
access. Sharing does not grant access to C8s credentials.

The shared group also contains the Kubernetes sandbox pause process. It keeps
the namespace alive across worker restarts and has no C8s credential mounts.
The isolation boundary separates this application group from C8s support
containers and the node. C8s does not provide process isolation between group
members. The applications can manage their processes within the signed workload
policy and the existing capability and exec rules.

This feature requires a C8s node image, CDS, and CLI that support
`c8s.allowlist/v2`. Pin the required component measurements before you enable
it. Older policy readers reject v2. Existing v1 policies keep private PID
namespaces.

## Declare the application group

Set `shareProcessNamespace: true` on each selected main container in the signed
allowlist entry. This field belongs to the C8s container policy, not the
Kubernetes container spec. The entry must pin every container's command,
arguments, mounts, and environment. Init containers, platform roles, static
pods, and containers with exec grants cannot request sharing.

For a prefill/decode deployment, declare two main containers in the pod and
mark their matching signed container policies. Leave any other application
policy unmarked. Each worker then has its own logs, metrics, resource limits,
and container lifecycle. C8s does not add Linux capabilities. If GPU transfer
needs `SYS_PTRACE`, authorize it separately through the existing capability
policy and check the applicable seccomp and driver requirements.

One pod supports one selected application group. All marked applications in
that pod share the group. Two groups that must remain separate need separate
pods. Separate group namespaces in one pod would require additional namespace
holders and lifecycle management.

Selected applications form one process-access trust group. Their processes
can reach each other's process information and can potentially access each
other's files through `/proc/<pid>/root`. Give the group one compatible secret
and data-access policy. Mount isolation between selected members is not a
secret boundary.

## Enforcement

The webhook continues to reject pod-wide process sharing and host namespace
access. It keeps the injected mesh, certificate, secret, and volume containers
in their existing order and shape.

NRI selects members from complete launches admitted by signed policy. It does
not use container names or pod annotations as permission. Conflicting shared
and private declarations, or different shared policies for the same launch,
are refused. Names reserved for support containers are also refused.

The group identity is the SHA-256 fingerprint of the complete normalized
workload entry. It includes the secret and network grants. A pod's group binds
to one fingerprint. Containers authorized by a different entry cannot join it.

The group uses the pod sandbox's PID namespace. Its pause process remains the
namespace's initial process. NRI proves that the namespace belongs to the
sandbox and differs from the node namespace. It pins the namespace with a
node-only bind mount. The path does not follow a worker PID that can be reused.

Only the proved PID namespace edit is allowed. Other namespace edits and
network-device edits remain refused. The runtime wrapper checks a node-only
grant that binds the container, sandbox, pod UID, path, and kernel namespace
identity. A support role cannot use this grant. The privilege, user-namespace,
identity, mount, capability, and exec checks still apply.

The admission inventory records the observed group fingerprint. Workload
matching and secret release require that evidence to match the signed entry.
A missing or different fingerprint fails the match. The existing node
attestation, workload certificate, and secret-release checks still apply.

## Restarts and policy changes

Worker restarts join the same pinned sandbox namespace. Recovery checks the
stored grants, the running process namespaces, the current policy, and the
group fingerprint. Historical stopped containers retain their admitted group
evidence. Removing a container removes its grant. Removing the sandbox removes
the namespace pin.

A change to the group workload policy changes its fingerprint. Recreate the
pod to use that policy. The existing revocation checks reject running launches
whose old group no longer matches. The group cannot switch policy while the
sandbox remains in use.

## Runtime evidence and limits

The node build pins RKE2 `v1.36.4+rke2r1`. Its
[runtime build](https://github.com/rancher/rke2/blob/v1.36.4%2Brke2r1/Dockerfile#L151)
uses containerd `v2.3.4-k3s1.36`, with NRI `v0.12.0`.
That runtime applies per-container namespace adjustments through
[its NRI adapter](https://github.com/k3s-io/containerd/blob/v2.3.4-k3s1.36/internal/cri/nri/nri_api_linux.go#L372)
and the
[NRI namespace generator](https://github.com/containerd/nri/blob/v0.12.0/pkg/runtime-tools/generate/generate.go#L491).
No containerd fork or pod-wide sharing is required for this path.

Linux namespace and unit tests do not prove GPU KV transfer or confidential
platform behavior. Before production use, test the built C8s image on the
target CVM. Verify application-to-application process access, support-container
isolation, attestation, workload identity, secret release, revocation, plugin
recovery, and worker restarts. Then test native GPU KV transfer with the target
driver, seccomp policy, and GPU configuration.
