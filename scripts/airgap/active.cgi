#!/usr/bin/env python3
"""Serve the active selection from the trusted authority under its pinned TLS leaf."""

import os
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

state = Path(os.environ.get("C8S_SITE_STATE", "/etc/c8s/site"))
challenge = os.environ.get("HTTP_X_C8S_CHALLENGE", "")
if os.environ.get("REQUEST_METHOD") != "GET" or not re.fullmatch(
    "[0-9a-f]{64}", challenge
):
    print("Status: 400 Bad Request\r\nCache-Control: no-store\r\n\r")
    sys.exit(0)
try:
    instant = datetime.fromisoformat(
        subprocess.check_output([state / "site-time"], timeout=8, text=True).strip()
    )
    if instant.utcoffset() != UTC.utcoffset(instant):
        raise ValueError("expected site UTC")
    selection = (state / "active").read_bytes()
except (OSError, ValueError, subprocess.SubprocessError):
    print("Status: 503 Service Unavailable\r\nCache-Control: no-store\r\n\r")
    sys.exit(0)
sys.stdout.buffer.write(
    (
        "Content-Type: application/json\r\nCache-Control: no-store\r\n"
        f"X-C8s-Time: {instant.isoformat()}\r\nX-C8s-Challenge: {challenge}\r\n\r\n"
    ).encode()
    + selection
)
