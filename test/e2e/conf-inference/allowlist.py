#!/usr/bin/env python3
"""Build the confidential-inference allowlist with the c8s under test.

This is confidential-inference's scripts/generate-release-allowlist.py
`generate()`, run from the pinned checkout, with two changes that make it
test this c8s build instead of the release's pinned one:

- the core entries are this build's allowlist-seed.json (`c8s node-image
  render`), not the seed recorded in the confidential-inference repository;
- the binary under test derives and lints, so the sourceCommit pin check of
  `generate()` is not run.

Writes app.json (the application entries, for launch-config --workloads)
and allowlist.json (seed plus application entries, for `c8s allowlist
upload`), both in canonical form.
"""

from __future__ import annotations

import argparse
import json
import runpy
import subprocess
import tempfile
from pathlib import Path

import yaml


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ci", type=Path, required=True, help="confidential-inference checkout at the pinned commit")
    parser.add_argument("--values", type=Path, action="append", required=True, help="helm values files, in order")
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--seed", type=Path, required=True, help="allowlist-seed.json of this c8s build")
    parser.add_argument("--c8s", type=Path, required=True, help="the c8s binary under test")
    parser.add_argument("--c8s-release", required=True, help="newest c8s tag this build contains; selects generator behavior")
    parser.add_argument("--canonical-tool", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    # The generator runs its commands from the checkout root.
    args.c8s, args.canonical_tool = args.c8s.resolve(), args.canonical_tool.resolve()

    gen = runpy.run_path(str(args.ci / "scripts/generate-release-allowlist.py"))
    policy = json.loads(args.policy.read_text())
    chart = policy["chart"]
    rendered = subprocess.run(
        ["helm", "template", chart["release"], str(args.ci / "helm/confidential-inference"),
         "--namespace", chart["namespace"], "--kube-version", chart["kubeVersion"],
         *[arg for path in args.values for arg in ("--values", str(path))]],
        check=True, capture_output=True, text=True,
    ).stdout
    controllers = gen["controllers"]([d for d in yaml.safe_load_all(rendered) if isinstance(d, dict)])
    expected = {item["controller"] for item in policy["workloads"]}
    if set(controllers) != expected:
        raise SystemExit(f"chart workloads {sorted(controllers)} differ from the policy {sorted(expected)}")

    seed = json.loads(args.seed.read_text())["workloads"]
    core_digests = {c["digest"] for entry in seed.values()
                    for c in entry.get("initContainers", []) + entry.get("containers", [])}
    images = {c["image"] for controller in controllers.values()
              for c in controller["spec"]["template"]["spec"].get("initContainers", [])
              + controller["spec"]["template"]["spec"]["containers"]}
    image_env = {image: gen["image_config"](image) for image in sorted(images)}

    workloads = {}
    for item in sorted(policy["workloads"], key=lambda value: value["name"]):
        controller = controllers[item["controller"]]
        pod = controller["spec"]["template"]["spec"]
        env_policies, mount_policies = {}, {}
        for container in pod.get("initContainers", []) + pod["containers"]:
            name = container["name"]
            if gen["is_carved_out"](gen["effective_process"](container, image_env[container["image"]]),
                                    core_digests, args.c8s_release):
                env_policies[name] = mount_policies[name] = {"policy": "any"}
                continue
            env_policies[name] = {"policy": "exact",
                                  "values": gen["container_env"](controller, container, image_env, policy, None)}
            rules = gen["container_mounts"](controller, container, None, c8s_release=args.c8s_release)
            mount_policies[name] = {"policy": "exact", "rules": rules} if rules else {"policy": "deny"}
        reads = sorted(set(item.get("secretReads", [])) | set(gen["volume_reads"](controller)))
        explicit = json.loads(json.dumps(controller))
        explicit_pod = explicit["spec"]["template"]["spec"]
        for field in ("initContainers", "containers"):
            if field in explicit_pod:
                explicit_pod[field] = [gen["effective_process"](c, image_env[c["image"]]) for c in explicit_pod[field]]
        workloads[item["name"]] = gen["derive"](args.c8s, item["name"], explicit, env_policies, mount_policies, reads)

    if collisions := set(workloads) & set(seed):
        raise SystemExit(f"application entries collide with the seed: {sorted(collisions)}")
    args.out_dir.mkdir(parents=True, exist_ok=True)
    app = gen["canonicalize"]({"schema": "c8s.allowlist/v1", "workloads": workloads}, args.canonical_tool)
    full = gen["canonicalize"]({"schema": "c8s.allowlist/v1", "workloads": {**seed, **workloads}},
                               args.canonical_tool)
    (args.out_dir / "app.json").write_bytes(app)
    (args.out_dir / "allowlist.json").write_bytes(full)
    with tempfile.TemporaryDirectory() as directory:
        for name, data in (("app.json", app), ("allowlist.json", full)):
            (Path(directory) / name).write_bytes(data)
            gen["lint"](args.c8s, Path(directory) / name, set())


if __name__ == "__main__":
    main()
