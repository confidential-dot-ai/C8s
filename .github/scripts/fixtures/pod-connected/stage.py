#!/usr/bin/env python3
"""Offline native-TDX input renderer. Never calls kubectl or creates resources."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess

PYTHON = "docker.io/library/python@sha256:5dcbe6043e931f65945060c7a991d55035191d7dfc52c8bed14468e95b8f7b9a"
EXCLUDED = [ipaddress.ip_network(value) for value in ("10.0.2.0/24", "10.52.0.0/16", "10.53.0.0/16", "10.255.254.0/30", "169.254.0.0/16")]


def write(path, value):
    data = value if isinstance(value, bytes) else (json.dumps(value, indent=2) + "\n").encode()
    with open(path, "xb") as output:
        output.write(data)


def command(cli, *args):
    result = subprocess.run([str(cli), *map(str, args)], capture_output=True, timeout=60, check=False)
    if result.returncode:
        raise RuntimeError("c8s command failed: " + result.stderr.decode(errors="replace")[-1000:])
    return result.stdout


def metadata(args, side):
    return {"name": args.name + "-" + side, "namespace": args.namespace,
            "labels": {"ci.confidential.ai/managed": "true", "ci.confidential.ai/resource": "pod-connected-acceptance",
                       "ci.confidential.ai/acceptance": args.name}}


def services(args):
    items = []
    for side in ("server", "a", "b"):
        ports = ([{"name": "cds", "port": 30808, "targetPort": 30808},
                  {"name": "api", "port": 6443, "targetPort": 6443}] if side == "server" else
                 [{"name": "app", "port": 8080, "targetPort": 8080}])
        ports.append({"name": "status", "port": 8443, "targetPort": 8443})
        for port in ports:
            port["protocol"] = "TCP"
        items.append({"apiVersion": "v1", "kind": "Service", "metadata": metadata(args, side), "spec": {
            "type": "ClusterIP", "ipFamilyPolicy": "SingleStack", "ipFamilies": ["IPv4"],
            "publishNotReadyAddresses": True, "selector": {"kubevirt.io/domain": args.name + "-" + side}, "ports": ports}})
    write(args.out, {"apiVersion": "v1", "kind": "List", "items": items})


def allocated(args):
    result = {}
    for service in json.loads(args.services.read_text())["items"]:
        meta, spec = service["metadata"], service["spec"]
        if meta.get("namespace") != args.namespace or not meta.get("uid"):
            raise ValueError("Service namespace/UID is missing or different")
        side = next((s for s in ("server", "a", "b") if meta["name"] == args.name + "-" + s), None)
        if not side or side in result:
            raise ValueError("unexpected or duplicate Service")
        if spec.get("selector") != {"kubevirt.io/domain": args.name + "-" + side}:
            raise ValueError("Service selector differs")
        address = ipaddress.IPv4Address(spec["clusterIP"])
        if address.is_loopback or address.is_unspecified or any(address in network for network in EXCLUDED):
            raise ValueError("Service IP overlaps a guest or excluded network")
        required = {30808: 30808, 8443: 8443, 6443: 6443} if side == "server" else {8080: 8080, 8443: 8443}
        actual = {p["port"]: p["targetPort"] for p in spec["ports"] if p.get("protocol", "TCP") == "TCP"}
        if actual != required:
            raise ValueError("Service ports differ")
        result[side] = {"ip": str(address), "uid": meta["uid"]}
    if set(result) != {"server", "a", "b"} or len({v["ip"] for v in result.values()}) != 3:
        raise ValueError("expected three distinct allocated Services")
    return result


def bundle(args):
    endpoints = allocated(args)
    raw = args.manifest.read_bytes()
    if hashlib.sha256(raw).hexdigest() != args.manifest_sha256:
        raise ValueError("exact-image manifest digest mismatch")
    manifest = json.loads(raw)
    if manifest.get("build", {}).get("platform") != "tdx" or any(not re.fullmatch("[0-9a-f]{96}", manifest["tdx"].get(k, "")) for k in ("mrtd", "rtmr1", "rtmr2")):
        raise ValueError("complete TDX manifest required")
    if not re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", args.mesh_image):
        raise ValueError("exact measured mesh image reference required")
    args.out.mkdir(mode=0o700)
    out = args.out.resolve()
    write(out / "manifest.json", raw)
    policy = json.loads(command(args.cli, "measurements", "derive", args.manifest, "--tee", "tdx"))
    if len(policy["measurements"]) != 1:
        raise ValueError("exactly one TDX image tuple required")
    pins = []
    for side in ("a", "b"):
        command(args.cli, "keys", "new", "--out", out / (side + ".key"), "--pub-out", out / (side + ".pub"))
        pin = dict(policy["measurements"][0])
        pin.update({"name": "pod-" + side, "approver_key": (out / (side + ".pub")).read_text()})
        pins.append(pin)
    policy["measurements"] = pins
    write(out / "pod-image-policy.json", policy)
    script = Path(__file__).with_name("app.py").read_text()
    config = {"peers": [endpoints[s]["ip"] for s in ("a", "b")], "dnsIPv4": "1.1.1.1",
              "podUID": args.name, "collectorURL": args.collector_url}
    argv = ["-u", "-c", script, json.dumps(config, separators=(",", ":"))]
    checker_config = dict(config, mode="checker")
    checker_argv = ["-u", "-c", script, json.dumps(checker_config, separators=(",", ":"))]
    security = {"runAsNonRoot": True, "runAsUser": 1500, "runAsGroup": 1500,
                "allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}}
    container = {"name": "app", "image": PYTHON, "command": ["/usr/local/bin/python3"], "args": argv,
                 "securityContext": security, "ports": [{"name": "http", "containerPort": 8080, "protocol": "TCP"}],
                 "readinessProbe": {"httpGet": {"path": "/ready", "port": 8080}, "periodSeconds": 5, "timeoutSeconds": 2, "failureThreshold": 1},
                 "livenessProbe": {"httpGet": {"path": "/live", "port": 8080}, "periodSeconds": 10, "timeoutSeconds": 2, "failureThreshold": 6},
                 "resources": {"requests": {"cpu": "100m", "memory": "64Mi"}, "limits": {"cpu": "1", "memory": "256Mi"}}}
    checker_container = {"name": "checker", "image": PYTHON, "command": ["/usr/local/bin/python3"], "args": checker_argv,
                         "securityContext": security, "resources": {"requests": {"cpu": "50m", "memory": "32Mi"},
                         "limits": {"cpu": "1", "memory": "128Mi"}}}
    pod = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "connected", "namespace": "acceptance", "uid": args.name},
           "spec": {"automountServiceAccountToken": False, "restartPolicy": "Never", "containers": [container, checker_container]}}
    write(out / "pod.json", pod)
    rule = {"digest": PYTHON.split("@")[1], "image": PYTHON,
            "command": {"policy": "exact", "argv": container["command"]}, "args": {"policy": "exact", "argv": argv}, "mounts": {"policy": "any"}}
    checker_rule = dict(rule, args={"policy": "exact", "argv": checker_argv})
    workloads = {"schema": "c8s.allowlist/v1", "workloads": {"connected": {"containers": [rule, checker_rule]}}}
    write(out / "pod-workloads.json", workloads)
    workloads["workloads"]["pod-mesh-membership"] = {"containers": [{"digest": args.mesh_image.split("@")[1], "image": args.mesh_image,
        "command": {"policy": "exact", "argv": ["/app/c8s", "armtls-mesh"]},
        "args": {"policy": "exact", "argv": ["--cert-path=/etc/c8s/certs/tls.crt", "--key-path=/etc/c8s/certs/tls.key", "--ca-path=/etc/c8s/certs/ca.crt"]},
        "mounts": {"policy": "any"}}]}
    write(out / "server-workloads.json", workloads)
    command(args.cli, "node", "launch-config", "new", "--out", out / "server", "--cluster-id", args.name,
            "--server-name", args.name + "-server", "--image-manifest", out / "manifest.json",
            "--server-address", endpoints["server"]["ip"], "--workloads", out / "server-workloads.json",
            "--pod-image-policy-file", out / "pod-image-policy.json")
    for side in ("a", "b"):
        command(args.cli, "node", "launch-config", "new-pod", "--out", out / side, "--cluster-id", args.name,
                "--name", args.name + "-" + side, "--image-manifest", out / "manifest.json", "--launch-key", out / (side + ".key"),
                "--server-address", endpoints["server"]["ip"], "--server-public-key", out / "server/server/pubkey",
                "--pod-manifest", out / "pod.json", "--workloads", out / "pod-workloads.json",
                "--mesh-peer", endpoints["a"]["ip"] + ":8080", "--mesh-peer", endpoints["b"]["ip"] + ":8080")
    write(out / "identity.json", {"source": args.source, "manifestSHA256": args.manifest_sha256,
          "applicationImage": PYTHON, "meshImage": args.mesh_image, "services": endpoints,
          "samePodManifestSHA256": hashlib.sha256((out / "pod.json").read_bytes()).hexdigest(),
          "expectedDigests": [PYTHON.split("@")[1], args.mesh_image.split("@")[1]],
          "scope": "native KubeVirt TDX hardware; no Cloud API or dynamic endpoint discovery claim"})
    print(json.dumps({"output": str(out), "scope": "offline inputs only", "serviceIPs": endpoints}, indent=2))


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    for mode in ("services", "bundle"):
        p = sub.add_parser(mode)
        p.add_argument("--name", required=True)
        p.add_argument("--namespace", default="confai-images")
        p.add_argument("--out", type=Path, required=True)
    p = sub.choices["bundle"]
    p.add_argument("--services", type=Path, required=True)
    p.add_argument("--cli", type=Path, required=True)
    p.add_argument("--manifest", type=Path, required=True)
    p.add_argument("--manifest-sha256", required=True)
    p.add_argument("--source", required=True)
    p.add_argument("--mesh-image", required=True)
    p.add_argument("--collector-url", default="")
    args = parser.parse_args()
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,35}[a-z0-9]", args.name):
        parser.error("name must be a short RFC1123 run identifier")
    (services if args.mode == "services" else bundle)(args)


if __name__ == "__main__":
    main()
