# Workload entries

A workload entry names the containers a pod may run, in the format
`c8s allowlist` writes, CDS serves, and every node enforces.

One invariant runs through it: policy is looked up by container digest, and an
absent `command`, `args`, or `mounts` policy denies. For why, see
[allowlist-and-capabilities.md](allowlist-and-capabilities.md).

## Document shape

```json
{
  "schema": "c8s.allowlist/v1",
  "workloads": {
    "vllm-llama": {
      "label": "docker.io/vllm/vllm-openai:v0.6.3",
      "initContainers": [],
      "containers": [{
        "digest": "sha256:<vllm>",
        "command": {"policy": "exact", "argv": ["python3"]},
        "args": {"policy": "exact", "argv": ["-m", "vllm.entrypoints.openai.api_server"]},
        "mounts": {"policy": "exact", "rules": [
          {"destination": "/mnt/c8s-data/config", "kind": "data"}
        ]},
        "env": {"policy": "match", "variables": {
          "HOSTNAME": {"exact": "vllm-llama"},
          "MODEL_DIR": {"exact": "/mnt/c8s-data/config"}}},
        "capabilities": ["SYS_PTRACE"]
      }],
      "secrets": {"policy": "allow", "read": ["/tenant-a/**"]},
      "egress": [{"cidr": "203.0.113.7/32", "port": 443}],
      "hostPorts": [{"protocol": "TCP", "hostPort": 9443, "containerPort": 8000}]
    }
  }
}
```

`schema` is the format identity and the first field of the canonical
serialization, so a malformed or foreign body fails loudly instead of parsing
as an empty policy. `label`, and a container's optional `image`, are
informational. Authored documents are parsed strictly.

## Entry names

A name matches `[A-Za-z0-9][A-Za-z0-9._-]*`, because it is used verbatim as a
URL path segment, and is at most 63 bytes, the Kubernetes label-value length,
so the same string can be a `confidential.ai/cw` value and a matched-workload
stamp. That bound applies on write; a served document is parsed leniently, and
an over-long entry is dropped from it with a warning.

## `command` and `args`

Both are matched against the container's effective argv — the OCI
`process.args` assembled from the image config and any pod-spec override.
`command` is an exact prefix, `args` governs the remainder.

| `policy` | `command` (a prefix) | `args` (the remainder) |
|---|---|---|
| `exact` | the argv must start with its `argv` | the remainder must equal its `argv` |
| `any` | no constraint | no constraint |
| `deny` | the whole argv must be empty | there must be no remainder |

An `exact` policy requires a non-empty `argv`, `any` and `deny` take none, and
an absent policy is `deny` — so `command: deny` admits only an empty argv, and
lint reports that the container can never start.

## `env`

A policy constrains the complete launch environment, image defaults and runtime
additions included.

| `policy` | Admits |
|---|---|
| `any` | any environment; this is the default when `env` is absent |
| `deny` | an observed empty environment |
| `exact` | an environment equal to `values` |
| `match` | exactly the variable names in `variables`, each satisfying its matcher |

A matcher is `{"exact": "<value>"}`, which pins the string including `""`, or
`{"present": true}`, which accepts any value — one form per variable, and a
missing or additional variable is rejected. An empty `variables: {}` requires
an empty environment, an empty `exact.values` normalizes to `deny`, and missing
evidence fails `exact`, `deny`, and `match`.

A `match` policy lists at most 128 variables totalling at most 4 KiB of names,
the bounds within which a node reports per-variable evidence, and one entry's
containers may together need at most 512 KiB of it. Set `enableServiceLinks:
false` on pods that use `match`. Lint rejects `present` on the loader variables
— `PATH`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `GLIBC_TUNABLES`,
`BASH_ENV`, `ENV`, and the `PYTHON*`, `NODE_*`, `JAVA*`, `PERL5*`, and `RUBY*`
ones — a list that is not exhaustive.

## `mounts`

A policy constrains the bind mounts in the final OCI specification.

| `policy` | Admits |
|---|---|
| `deny` | platform mounts only; this is the default when `mounts` is absent |
| `any` | any mounts |
| `exact` | platform mounts, plus a non-platform set equal to `rules` |

Platform mounts are the node's own, admitted without a rule: `/etc/hosts`,
`/etc/hostname`, `/etc/resolv.conf`, `/dev/shm`, `/dev/termination-log`, the
service-account projected volume, and the read-only binds the node adds to an
injected pod's credential clients. Each counts only at its destination from
this pod's or sandbox's own source: a matching destination proves nothing.

A rule has a `destination` (a clean absolute path, unique within the
container), a `kind`, and for host kinds a `source` and `readOnly`; `exact`
needs at least one rule.

| `kind` | Requires | Admits |
|---|---|---|
| `emptyDir` | no `readOnly` | one of this pod's `emptyDir` volumes on memory or encrypted storage |
| `data` | a destination under `/mnt/c8s-data/` | any other volume of this pod, on memory or encrypted storage |
| `host` | a clean absolute `source`; `readOnly` matched exactly | a host bind whose source commitment and access mode match |
| `nodeRootFile` | the same `source`, plus `readOnly: true` | the same, and node-root provenance for the file |

A `source` naming a pod volume is refused in JSON: only a measured base does
that.

Node-root provenance is a plain bind of a regular file reached directly through
the node's read-only dm-verity root, with no symlink or intervening mount. The
node must mount `/` read-only from one whole-device SHA-256 `verity` target,
with exactly one matching `roothash=` on its measured kernel command line and
no overlay above it; a node that does not denies every `nodeRootFile` rule and
logs `node-root provenance unavailable` at startup. Lint allows a
`nodeRootFile` rule on a pinned search path, where a `data` or `host` rule is
an error.

## `capabilities`

The capabilities a container may hold beyond the node's default set, named as a
pod spec names them: the kernel's constant without the `CAP_` prefix, such as
`SYS_PTRACE`. A declarable name is a Linux capability outside the container
runtime's default set, less `NET_ADMIN`, `NET_RAW`, `SETUID` and `SETGID`,
which rewrite the pod's mesh ruleset or take a platform role's reserved
identity. Every name is declarable and is listed once. An entry declaring a
capability pins every container's launch: `command`, `args` and `mounts` not
`any`, and `env` constrained. A node holds a container to its default set plus
what the entry admitting its whole launch declares, and a container on a
platform role to none.

## `secrets`

`allow` or `deny` only; there is no `any`. An `allow` grant needs at least one
`read` path and may add a `write` list under the same path rules; paths are
absolute and clean, and the only wildcard is a trailing `/**`, matching
strictly beneath its base. A grant requires every container of the entry to pin
its argv (`command` and `args` `exact` or `deny`) and its mounts (`deny`, or
`exact` with no `host` rule; read-only `nodeRootFile` is allowed). Release:
[secrets.md](secrets.md).

## `egress`

Up to 8 egress entries, each a range and one TCP port a pod this entry claims
reaches directly, outside the mesh. An entry has exactly the members `cidr` and
`port`. A range carries no host bits, is listed once, is written as IPv4 when it
is IPv4, and is no broader than `/16` (IPv4) or `/48` (IPv6). Ranges that are
not unicast hosts are refused: `/0`, loopback, link-local, multicast, reserved
and broadcast, and the IPv6 forms that embed IPv4 addresses. An entry with
egress pins its launch as a grant does and pins every container's `env`:
`deny`, `exact`, or `match` with only `exact` matchers and no `serviceLinks`,
since a variable such
as `HTTPS_PROXY` or `SSL_CERT_FILE` can redirect or disable the application TLS
that protects an exit. A pod's `HOSTNAME` is its name unless the pod sets
`hostname`, so set it to pin `HOSTNAME`. A node refuses an exit that overlaps a
cluster range, its own address, the resolver, or CDS.

## `hostPorts`

The ports a pod this entry claims publishes on the node's own address. A
mapping has exactly the members `protocol` (`TCP`, `UDP`, or `SCTP`, spelled as
a pod spec spells it), `hostPort`, and `containerPort`, both between 1 and
65535. A protocol and host port pair is listed once; the same host port on two
protocols is two mappings. The node's own service ports are refused: 1019 (the
workload inventory), 2379 and 2380 (etcd), 6443 (the Kubernetes API), 8443
(credential release), 9345 (the agent join endpoint), and 10250 (the kubelet).
An entry with host ports pins every container's launch: `command`, `args` and
`mounts` not `any`, and `env` constrained. A node refuses a pod publishing a
mapping no entry declares, and a container of such a pod unless the entry
declaring its mappings admits that launch.

## Component sets

The `components` section lists the component sets the cluster admits. A set is
one release's entries for the containers c8s itself runs: the injected
sidecars, the router and the node services.

```json
{
  "schema": "c8s.allowlist/v1",
  "workloads": {},
  "components": {
    "0.43.0": {
      "entries": {
        "c8s-mesh-endpoint": {
          "containers": [{
            "digest": "sha256:<mesh>",
            "role": "mesh",
            "command": {"policy": "exact", "argv": ["/app/c8s", "armtls-mesh"]},
            "args": {"policy": "any"},
            "mounts": {"policy": "exact", "rules": [
              {"destination": "/run/c8s", "kind": "emptyDir", "source": "c8s-run"}
            ]}
          }]
        }
      }
    },
    "0.42.1": {
      "retire": {"deadline": "2026-12-01T00:00:00Z"},
      "entries": {}
    }
  }
}
```

A set is keyed by the release that built it, `MAJOR.MINOR.PATCH` with no `v`
and no leading zeros. Each entry has the shape of a workload entry and may
carry two fields a workload entry may not: a container's `role`, and the
entry's `nodeService`, which marks the entry of a node service — a pod of one
container serving the whole node. A set entry's mount rule may also name one of
the pod's own volumes in `source`.

A `nodeService` entry grants its container the host privilege a worker's static
pod holds, host ports aside: a host namespace, a host bind mount, a device and
the marks of a privileged container, which every other pod of a node is refused
([allowlist-and-capabilities.md](allowlist-and-capabilities.md#host-privilege)).
It is granted while all three hold:

- the container's launch is the one the entry pins — digest, `command`, `args`,
  `env` and `mounts`;
- it is the only container of its pod;
- no other pod on the node runs that entry's container.

A launch the entry admits in a pod that breaks the second or third rule is
refused, naming the rule. Host ports stay refused unless the entry declares
them. A retiring set admits its node service until its deadline, so the pod
starts again after a crash.

A set without `retire` is current. A set with one is retiring. A set is in
force while it is current, or retiring with its deadline still ahead. A
deadline is RFC 3339 UTC with second precision (`2026-12-01T00:00:00Z`); any
other spelling is refused, so one instant has one form in the signed bytes.

Every set is checked:

- the version is `MAJOR.MINOR.PATCH` with major version `0`;
- a `retire` carries a deadline;
- every entry is a valid workload entry;
- every container names one of the roles `mesh`, `credentials`, `router`,
  `acme` and `upstream` or none, pins its `command` and its `mounts` (`exact`),
  and declares no `capabilities`;
- no two containers of the set share a launch — the same digest under the same
  `command` argv and `args` policy;
- a `nodeService` entry has one container and no init container, and its
  `command`, `args`, `env` and `mounts` are all `exact`.

Sets are operator-written: the measured CDS configuration seeds the workloads
section only, and a seed document naming a `components` section fails startup.

A write is refused whole when one of its sets fails a check, names an
unsupported major version, or carries a field this release does not know. A
node parses what it is served leniently: it drops that set alone with a
warning and applies the rest of the document. A `role` or a `nodeService`
under `workloads` is refused on write and dropped from a served document.

## Matching

A declared container admits a running one when the digest is equal and every
policy admits what the node observed. Under `command: exact` with `mounts: any`
it is refused when a non-platform mount covers the pinned executable's absolute
path — a mount at `/usr/bin` and one at `/usr/bin/python3` both block a
`command` pinned to `/usr/bin/python3`. The executable is the running argv's
first element; a relative one is not checked, so pin an absolute path. An entry describes a running set when every running container is
one it declares and every main container it declares runs; a declared init
container may have exited, so it need not.

## `c8s allowlist`

Reads are unauthenticated; writes are signed with the operator key from
`--operator-key` or `C8S_OPERATOR_KEY`. Persistent flags: `--url`,
`--measurements`, `--measurements-file`, `--image-policy-file`, `--timeout`
(15s), `-o text|json`, `--insecure`.

| Subcommand | Does |
|---|---|
| `list` | print the current entries |
| `get <name>` | print one entry as canonical JSON |
| `export [file]` | write the whole document as canonical JSON |
| `diff <file>` | show how a file differs from the live document; `--exit-code` |
| `lint <file\|->` | validate and report findings; `--online`, `--strict`, `--seed <file>` |
| `inspect-image <ref>` | print an image's digest and baked `Entrypoint`/`Cmd` |
| `derive <name> <file\|->` | build an entry from a Pod, Deployment, StatefulSet, or DaemonSet |
| `add <digest> <image>` | write `<image basename>-<first 12 hex of digest>`, with `any` for command, args, env, and mounts; `--dry-run` |
| `apply <file\|->` | upsert entries, each replaced whole; `--dry-run` |
| `edit <name>` | fetch, `$EDITOR`, validate, diff, confirm, apply |
| `delete <name>...` | delete entries |
| `upload <file>` | replace the whole document; `--force`, `--require`, `--cvm-mode`, `--strict`, `--dry-run` |
| `components add --set-file <file>` | add a component set; `--retire VERSION=DEADLINE`, `--remove VERSION`, `--force`, `--dry-run` |
| `components retire <version> <deadline>` | set or move a set's deadline; `--force` |
| `components unretire <version>` | take a set's deadline off |
| `components remove <version>` | drop a set; `--force` |
| `components list` | print every set, its state, entry count and digest |

`derive` takes `--env=any|deny` or `--env-file` (exactly one is required),
`--mounts=any|deny` or `--mounts-file` (omitted leaves every container at
`deny`), `--label`, and `--secret-read`. A policy file maps container names to
policies and must cover every init and main container the entry declares.
`derive` reads an unset command or args from the image config with `crane`, and
drops the containers C8s injects. For a pod that sets
`confidential.ai/c8s-secrets`, it adds the secrets mount the webhook injects to
each `deny` or `exact` policy: an `emptyDir` rule at `/run/c8s/secrets`, or
wherever the container already mounts the volume (`data` for a `subPath`
mount).

`apply`, `upload`, and `edit` show a diff before they write. `apply` and
`upload` lint the whole document first, and `add` checks its one entry against
the served ones: a lint error blocks the write, and `upload --strict` makes
warnings block it too. `delete` does neither.

Lint errors are documents that cannot work — a component executable with
`args`, `mounts`, or `env` left open, a loader variable left to the host, a
pinned `PATH`, `LD_LIBRARY_PATH`, `PYTHONPATH`, or `NODE_PATH` whose search
path overlaps a `data` or `host` mount, two entries no running set can tell
apart, and an entry another entry shadows. Warnings are judgements: an entry
with no containers, a `command: deny` container, a shared digest widened to
`any`, a tag-form label, a root-subtree grant, a grant whose containers pin no
environment value, and a stale chart shape `--seed` names.
