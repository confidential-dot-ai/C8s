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
- The worker's probes time out within the pod mesh's 5 s forwarding budget.
  The chart's longer timeouts make the webhook refuse the pod
  ("forwarded probe timeoutSeconds exceeds the 5s budget").

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


def patch(docs: list[dict], image: str) -> list[dict]:
    for doc in docs:
        kind, name = doc.get("kind"), doc["metadata"]["name"]
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
        for probe in ("startupProbe", "readinessProbe", "livenessProbe"):
            if probe in container:
                container[probe]["timeoutSeconds"] = min(container[probe].get("timeoutSeconds", 1), 5)
    return docs


if __name__ == "__main__":
    docs = [d for d in yaml.safe_load_all(sys.stdin) if isinstance(d, dict)]
    yaml.safe_dump_all(patch(docs, os.environ["SIM_IMAGE"]), sys.stdout, sort_keys=False)
