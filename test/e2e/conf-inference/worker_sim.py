#!/usr/bin/env python3
"""Swap the inference workers in a rendered confidential-inference chart for
llm-d-inference-sim.

The chart's simulator mode runs the sglang simulator in the 14 GB CUDA
sglang image. This test checks the allowlist and attestation contract, not
inference, so each worker's sglang container runs the small pinned
llm-d-inference-sim instead, with the served model name and port the chart
rendered. run.sh applies this output and allowlist.py derives the entries
from it, so both see the same pods.

Filter: rendered YAML on stdin, patched YAML on stdout. SIM_IMAGE is in
pins.env.
"""

from __future__ import annotations

import os
import sys

import yaml


def patch(docs: list[dict], image: str) -> list[dict]:
    for doc in docs:
        if doc.get("kind") != "StatefulSet" or not doc["metadata"]["name"].startswith("inference-worker-"):
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
