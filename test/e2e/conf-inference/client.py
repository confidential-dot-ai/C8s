#!/usr/bin/env python3
"""Client checks through TEErminator's verifying proxy.

mint-key: create an API key with a request signed by the admin signer key,
  as the admin VM does (gateway admin_auth.rs, canonical request v1).
complete: GET /v1/models and one chat completion with that key.
attestation: the C8s part of confidential-inference's
  verify-public-attestation.py: the gateway's /attestation names the cds
  front-door mode, the allowlist it reports is the one the front door serves,
  and every receipt names a workload of that allowlist.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request


def request(url: str, method: str = "GET", body: bytes | None = None, headers: dict | None = None) -> bytes:
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    with urllib.request.urlopen(req, timeout=120) as response:
        if response.status not in (200, 201):
            raise SystemExit(f"{method} {url}: HTTP {response.status}")
        return response.read()


def mint_key(args: argparse.Namespace) -> None:
    path = "/admin/v1/api-keys"
    body = json.dumps({"name": f"c8s-e2e-{os.urandom(4).hex()}", "tags": [], "audit": {"actor": "c8s-e2e", "reason": "c8s ci"}}).encode()
    timestamp, nonce = str(int(time.time())), os.urandom(16).hex()
    body_hash = hashlib.sha256(body).hexdigest()
    canonical = f"v1\n{timestamp}\n{nonce}\nPOST\n{path}\n{body_hash}\n".encode()
    with tempfile.NamedTemporaryFile() as message:
        message.write(canonical)
        message.flush()
        signature = subprocess.run(["openssl", "dgst", "-sha256", "-sign", args.admin_key, message.name],
                                   check=True, capture_output=True).stdout
    created = json.loads(request(args.proxy + path, "POST", body, {
        "content-type": "application/json",
        "idempotency-key": nonce,
        "x-admin-signature-version": "v1",
        "x-admin-timestamp": timestamp,
        "x-admin-nonce": nonce,
        "x-admin-body-sha256": body_hash,
        "x-admin-signature": base64.urlsafe_b64encode(signature).rstrip(b"=").decode(),
    }))
    print(created["apiKey"])


def complete(args: argparse.Namespace) -> None:
    auth = {"authorization": f"Bearer {args.api_key}", "content-type": "application/json"}
    models = json.loads(request(args.proxy + "/v1/models", headers=auth))
    model = models["data"][0]["id"]
    chat = {"model": model, "max_tokens": 16, "messages": [{"role": "user", "content": "Say hello."}]}
    answer = json.loads(request(args.proxy + "/v1/chat/completions", "POST", json.dumps(chat).encode(), auth))
    if not answer.get("choices"):
        raise SystemExit(f"the completion has no choices: {answer}")
    print(f"ok: {model} answered a chat completion")


def attestation(args: argparse.Namespace) -> None:
    nonce = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
    raw = request(f"{args.proxy}/attestation?nonce={nonce}")
    response = json.loads(raw)
    with open(args.allowlist, "rb") as handle:
        served = handle.read()
    workloads = json.loads(served)["workloads"]
    c8s = response["c8s"]
    problems = []
    if c8s["discovery"]["public_tls"]["mode"] != args.mode:
        problems.append(f"discovery public_tls.mode is {c8s['discovery']['public_tls']['mode']}, want {args.mode}")
    if c8s["activeAllowlist"]["sha256"] != "sha256:" + hashlib.sha256(served).hexdigest():
        problems.append("the gateway reports a different active allowlist than the front door serves")
    receipts = response.get("receipts", [])
    if response["schemaVersion"] == 2:
        names = {item["workload"] for item in receipts}
        if names != set(args.workload):
            problems.append(f"receipts name {sorted(names)}, want {sorted(args.workload)}")
        if missing := names - set(workloads):
            problems.append(f"receipt workloads {sorted(missing)} are not in the served allowlist")
        if response["nonce"] != nonce:
            problems.append("the response does not echo the nonce")
    if problems:
        print(json.dumps(response, indent=2)[:20000], file=sys.stderr)
        raise SystemExit("FAIL: " + "; ".join(problems))
    print(f"ok: /attestation v{response['schemaVersion']} matches the served allowlist and {args.mode} front door")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proxy", default="http://127.0.0.1:18080")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("mint-key").add_argument("--admin-key", required=True)
    sub.add_parser("complete").add_argument("--api-key", required=True)
    check = sub.add_parser("attestation")
    check.add_argument("--mode", required=True, choices=["cds", "acme"], help="the launch's front-door mode")
    check.add_argument("--allowlist", required=True, help="the bytes `teerminator allowlist fetch` wrote")
    check.add_argument("--workload", action="append", required=True)
    args = parser.parse_args()
    {"mint-key": mint_key, "complete": complete, "attestation": attestation}[args.command](args)


if __name__ == "__main__":
    main()
