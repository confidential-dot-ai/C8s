#!/usr/bin/env python3
"""Patch a rendered confidential-inference chart for the single test node.

- Each inference worker's sglang container runs the small pinned
  llm-d-inference-sim instead of the sglang simulator in the 14 GB CUDA
  image, with the served model name and port the chart rendered. This test
  checks the allowlist and attestation contract, not inference.
- The gateway dials the router through the operator's headless
  c8s-sglang-router Service. The chart hardcodes the sglang-router ClusterIP
  Service, whose VIP armtls-mesh does not intercept, so the cw guard drops
  the connection (C8s#933).
- No probe timeout exceeds the mesh's forwarded-probe budget (5 s), which
  the webhook enforces; the chart gives the worker's startup probe 10 s.
- The workloads' CDS egress also allows the node's CDS port. Since the
  enforcer mounts the node's own CDS endpoint into credential clients
  (#806, #814), c8s-cert dials <node IP>:30808, not the c8s-cds Service on
  8443 the chart's workloads-to-c8s-cds policy allows.

run.sh applies this output and allowlist.py derives the entries from it, so
both see the same pods.

Filter: rendered YAML on stdin, patched YAML on stdout. SIM_IMAGE is in
pins.env.
"""

from __future__ import annotations

import os
import sys

import yaml

ROUTER_URL = "http://c8s-sglang-router.confidential-inference.svc.cluster.local:30000"
PROBE_TIMEOUT_SECONDS = 5  # workloadclaims.MeshProbeTimeout
NODE_CDS_PORT = 30808


def patch(docs: list[dict], image: str) -> list[dict]:
    for doc in docs:
        kind, name = doc.get("kind"), doc["metadata"]["name"]
        if kind == "NetworkPolicy" and name == "workloads-to-c8s-cds":
            doc["spec"]["egress"].append({"ports": [{"protocol": "TCP", "port": NODE_CDS_PORT}]})
        for container in doc.get("spec", {}).get("template", {}).get("spec", {}).get("containers", []):
            for probe in ("startupProbe", "readinessProbe", "livenessProbe"):
                if probe in container:
                    container[probe]["timeoutSeconds"] = min(container[probe].get("timeoutSeconds", 1), PROBE_TIMEOUT_SECONDS)
        if kind == "Deployment" and name == "gateway":
            container = next(c for c in doc["spec"]["template"]["spec"]["containers"] if c["name"] == "gateway")
            next(e for e in container["env"] if e["name"] == "GATEWAY_INFERENCE_URL")["value"] = ROUTER_URL
        if kind != "StatefulSet" or not name.startswith("inference-worker-"):
            continue
        container = next(c for c in doc["spec"]["template"]["spec"]["containers"] if c["name"] == "sglang")
        flags = dict(arg.split("=", 1) for arg in container["args"] if arg.startswith("--") and "=" in arg)
        container["image"] = image
        container["command"] = ["/app/llm-d-inference-sim"]
        container["args"] = [f"--model={flags['--served-model-name']}", f"--port={flags['--port']}"]
    return docs


if __name__ == "__main__":
    docs = [d for d in yaml.safe_load_all(sys.stdin) if isinstance(d, dict)]
    yaml.safe_dump_all(patch(docs, os.environ["SIM_IMAGE"]), sys.stdout, sort_keys=False)
