# Workload entries

The format of the entries `c8s allowlist` writes, CDS serves, and every node
enforces. One invariant runs through it: policy is looked up by container
digest, and an absent `command`, `args`, or `mounts` policy denies. For why, see
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
          "HOSTNAME": {"present": true},
          "MODEL_DIR": {"exact": "/mnt/c8s-data/config"}}}
      }],
      "secrets": {"policy": "allow", "read": ["/tenant-a/**"]},
      "egress": [{"cidr": "203.0.113.7/32", "port": 443}]
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
egress pins its launch as a grant does, and a node refuses one that overlaps a
cluster range, its own address, the resolver, or CDS.

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
| `add <digest> <image>` | write `<image basename>-<first 12 hex of digest>`, admitting any command line; `--dry-run` |
| `apply <file\|->` | upsert entries, each replaced whole; `--dry-run` |
| `edit <name>` | fetch, `$EDITOR`, validate, diff, confirm, apply |
| `delete <name>...` | delete entries |
| `upload <file>` | replace the whole document; `--force`, `--require`, `--cvm-mode`, `--strict`, `--dry-run` |

`derive` takes `--env=any|deny` or `--env-file` (exactly one is required),
`--mounts=any|deny` or `--mounts-file` (omitted leaves every container at
`deny`), `--label`, and `--secret-read`. A policy file maps container names to
policies and must cover every init and main container the entry declares.
`derive` reads an unset command or args from the image config with `crane`, and
drops the containers C8s injects.

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
