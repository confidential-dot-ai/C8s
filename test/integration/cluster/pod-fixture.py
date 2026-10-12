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
        "--container",
        action="append",
        default=[],
        metavar="'IMAGE CMD...'",
        help="a further container, its image then its command as one shell-quoted string; "
        "named c2, c3, ... after the first",
    )
    args = parser.parse_args()

    container = {
        "name": "curl",
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
    for i, spec in enumerate(args.container, start=2):
        words = shlex.split(spec)
        pod["spec"]["containers"].append(dict(container, name=f"c{i}", image=words[0], command=words[1:]))
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
    print(json.dumps(pod))


if __name__ == "__main__":
    main()
