#!/usr/bin/env python3
"""Render the exact Restricted-compatible curl Pods used by the cluster lane."""

import argparse
import json
import shlex


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("client", "bad-label", "bad-hostnet", "front-door", "pvc"))
    parser.add_argument("name")
    parser.add_argument("namespace")
    parser.add_argument("image")
    parser.add_argument("command", nargs="+")
    parser.add_argument("--node", help="pin the pod to this node")
    parser.add_argument("--pull-policy", help="the container's imagePullPolicy")
    parser.add_argument(
        "--annotation",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="a pod annotation; repeatable",
    )
    parser.add_argument("--container-name", default="curl", help="the first container's name")
    parser.add_argument(
        "--supplemental-group",
        type=int,
        metavar="GID",
        help="a group the pod's processes are also members of",
    )
    parser.add_argument(
        "--container",
        action="append",
        default=[],
        metavar="'IMAGE CMD...'",
        help="a further container, its image then its command as one shell-quoted string; "
        "named c2, c3, ... after the first",
    )
    parser.add_argument(
        "--init-container",
        action="append",
        default=[],
        metavar="'IMAGE CMD...'",
        help="an init container, its image then its command as one shell-quoted string; "
        "named i1, i2, ...",
    )
    parser.add_argument("--label", action="append", default=[], metavar="KEY=VALUE", help="a pod label; repeatable")
    parser.add_argument("--host-network", action="store_true", help="share the node's network namespace")
    parser.add_argument(
        "--run-as-user",
        type=int,
        metavar="UID",
        help="the pod's user; 0 also lifts runAsNonRoot, since the two contradict",
    )
    parser.add_argument(
        "--add-capability",
        action="append",
        default=[],
        metavar="CAP",
        help="a capability every container gains, e.g. NET_BIND_SERVICE",
    )
    parser.add_argument(
        "--sysctl",
        action="append",
        default=[],
        metavar="NAME=VALUE",
        help="a pod sysctl; repeatable",
    )
    args = parser.parse_args()

    container = {
        "name": args.container_name,
        "image": args.image,
        "command": args.command,
        "securityContext": {
            "allowPrivilegeEscalation": False,
            "capabilities": {"drop": ["ALL"]},
        },
    }
    pod = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": args.name, "namespace": args.namespace},
        "spec": {
            "restartPolicy": "Never",
            "securityContext": {
                "runAsNonRoot": True,
                "runAsUser": 1000,
                "seccompProfile": {"type": "RuntimeDefault"},
            },
            "containers": [container],
        },
    }
    if args.node:
        pod["spec"]["nodeName"] = args.node
    if args.pull_policy:
        container["imagePullPolicy"] = args.pull_policy
    if args.annotation:
        pod["metadata"]["annotations"] = dict(a.split("=", 1) for a in args.annotation)
    if args.supplemental_group is not None:
        pod["spec"]["securityContext"]["supplementalGroups"] = [args.supplemental_group]
    if args.add_capability:
        container["securityContext"]["capabilities"]["add"] = args.add_capability
    if args.host_network:
        pod["spec"]["hostNetwork"] = True
    if args.run_as_user is not None:
        pod["spec"]["securityContext"]["runAsUser"] = args.run_as_user
        if args.run_as_user == 0:
            pod["spec"]["securityContext"]["runAsNonRoot"] = False
    if args.label:
        pod["metadata"]["labels"] = dict(label.split("=", 1) for label in args.label)
    for i, spec in enumerate(args.container, start=2):
        words = shlex.split(spec)
        pod["spec"]["containers"].append(dict(container, name=f"c{i}", image=words[0], command=words[1:]))
    for i, spec in enumerate(args.init_container, start=1):
        words = shlex.split(spec)
        pod["spec"].setdefault("initContainers", []).append(
            dict(container, name=f"i{i}", image=words[0], command=words[1:])
        )
    if args.mode == "bad-label":
        pod["metadata"]["labels"] = {"confidential.ai/cw": "rogue"}
    elif args.mode == "bad-hostnet":
        pod["spec"]["hostNetwork"] = True
    elif args.mode == "front-door":
        container["volumeMounts"] = [{"name": "ca", "mountPath": "/ca", "readOnly": True}]
        pod["spec"]["volumes"] = [{"name": "ca", "configMap": {"name": "it-mesh-ca"}}]
    elif args.mode == "pvc":
        container["volumeMounts"] = [{"name": "data", "mountPath": "/data"}]
        pod["spec"]["volumes"] = [
            {"name": "data", "persistentVolumeClaim": {"claimName": args.name}}
        ]
    # kubelet refuses every net.* sysctl for a pod in the node's network namespace.
    sysctls = [s for s in args.sysctl if not (pod["spec"].get("hostNetwork") and s.startswith("net."))]
    if sysctls:
        pod["spec"]["securityContext"]["sysctls"] = [
            {"name": name, "value": value} for name, value in (s.split("=", 1) for s in sysctls)
        ]
    print(json.dumps(pod))


if __name__ == "__main__":
    main()
