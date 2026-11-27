#!/usr/bin/env python3
"""Attest the router and request the pinned nginx response on one TLS connection."""

import base64
import hashlib
import http.client
import json
import os
import secrets
import ssl
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit


def request(conn: http.client.HTTPSConnection, path: str) -> bytes:
    conn.request("GET", path)
    resp = conn.getresponse()
    body = resp.read(1_048_577)
    if resp.status != 200 or len(body) > 1_048_576:
        raise ValueError(f"{path} returned HTTP {resp.status} or exceeded 1 MiB")
    return body


def probe(out: Path) -> None:
    url = urlsplit(os.environ["NGINX_URL"])
    if url.scheme != "https" or not url.hostname or url.username or url.fragment:
        raise ValueError("NGINX_URL must be the certified HTTPS route")
    ctx = ssl.create_default_context(cafile=str(out.parent / "mesh-ca.pem"))
    nonce = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
    conn = http.client.HTTPSConnection(url.hostname, url.port, context=ctx, timeout=30)
    try:
        conn.connect()
        conn.auto_open = 0
        assert conn.sock is not None
        cert = conn.sock.getpeercert(binary_form=True)
        if not cert:
            raise ValueError("router did not present a certificate")
        leaf = out / "router.pem"
        leaf.write_text(ssl.DER_cert_to_PEM_cert(cert))
        receipt = out / "router-receipt.json"
        receipt.write_bytes(request(conn, f"/.well-known/c8s/attest-lb?nonce={nonce}"))
        args = ["c8s", "verify", "--kind", "lb", "--mode", "attest-lb", "-o", "json"]
        args.extend(["--from-file", str(receipt), "--attestation-nonce", nonce])
        args.extend(["--observed-serving-cert", str(leaf)])
        args.extend(["--mesh-ca", str(out.parent / "mesh-ca.pem")])
        args.extend(["--route-digest", os.environ["ROUTE_DIGEST"]])
        args.extend(["--image-policy-file", os.environ["WORKER_PIN"]])
        args.extend(["--pin-policy", os.environ["ACCEPTED_POLICIES"]])
        args.extend(["--tdx-collateral-profile", os.environ["SITE_PROFILE"]])
        with (out / "router-verdict.json").open("w") as report:
            subprocess.run(args, check=True, timeout=90, stdout=report)
        verdict = json.loads((out / "router-verdict.json").read_bytes())
        if (
            verdict.get("verified") is not True
            or verdict.get("route_digest") != os.environ["ROUTE_DIGEST"]
        ):
            raise ValueError("router verdict did not verify the approved route")
        path = url.path or "/"
        if url.query:
            path += "?" + url.query
        body = request(conn, path)
        if hashlib.sha256(body).hexdigest() != os.environ["NGINX_BODY_SHA256"]:
            raise ValueError("response differs from the approved nginx sample body")
        (out / "nginx.body").write_bytes(body)
    finally:
        conn.close()


if __name__ == "__main__":
    try:
        probe(Path(sys.argv[1]))
    except (
        OSError,
        ValueError,
        subprocess.SubprocessError,
        http.client.HTTPException,
    ) as error:
        sys.exit(str(error))
