#!/usr/bin/env python3
"""Measure whether the target's signed GPU certificate status survives a media refresh."""

import argparse
import csv
import hashlib
import json
import re
import subprocess
import sys
import time
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path


def openssl(*args: str, data: bytes | None = None) -> str:
    result = subprocess.run(
        ["openssl", *args], check=False, input=data, capture_output=True, timeout=30
    )
    if result.returncode:
        error = result.stderr or result.stdout
        raise ValueError(error.decode(errors="replace").strip())
    return result.stdout.decode()


def cert_deadlines(pem: str) -> list[int]:
    certs = re.findall(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem, flags=re.DOTALL
    )
    dates = [
        openssl("x509", "-enddate", "-noout", data=cert.encode()) for cert in certs
    ]
    return [unix(date.removeprefix("notAfter=")) for date in dates]


def unix(date: str) -> int:
    return int(parsedate_to_datetime(date).timestamp())


def response_deadline(
    folder: Path,
    fingerprint: str,
    roots: Path,
    intermediates: Path,
    max_age: int,
    imported: int,
) -> tuple[int, str]:
    leaf = folder / "cert.pem"
    issuer = folder / "issuer.pem"
    actual = openssl("x509", "-in", str(leaf), "-sha256", "-fingerprint", "-noout")
    if actual.strip().split("=")[-1].replace(":", "").lower() != fingerprint:
        raise ValueError("certificate differs from enrolled SHA-256 fingerprint")
    openssl(
        "verify", "-trusted", str(roots), "-untrusted", str(intermediates), str(leaf)
    )
    openssl("verify", "-partial_chain", "-trusted", str(issuer), str(leaf))
    response = (folder / "ocsp.der").read_bytes()
    trust = ["-CAfile", str(roots), "-no-CApath", "-no-CAstore", "-no_explicit"]
    cert = ["-issuer", str(issuer), "-cert", str(leaf)]
    subject = ["-verify_other", str(intermediates), *cert]
    status = ["-no_nonce", "-validity_period", "0", "-resp_text"]
    report = openssl(
        "ocsp", "-respin", "/dev/stdin", *trust, *subject, *status, data=response
    )
    _, good, summary = report.rpartition(f"\n{leaf}: good\n")
    if not good:
        raise ValueError("missing signed good status for the enrolled certificate")
    dates = dict(
        re.findall(r"^\s*(This Update|Next Update): ([^\n]+)$", summary, re.MULTILINE)
    )
    issued = unix(dates["This Update"])
    if not issued <= imported < issued + max_age:
        raise ValueError("OCSP thisUpdate outside approved age at import")
    vendor_end = unix(dates["Next Update"]) if "Next Update" in dates else issued + 3600
    if vendor_end <= imported:
        raise ValueError("OCSP validity ended by import")
    deadline = min(
        vendor_end,
        issued + max_age,
        *cert_deadlines(leaf.read_text()),
        *cert_deadlines(issuer.read_text()),
        *cert_deadlines(report),
    )
    return deadline, hashlib.sha256(response).hexdigest()


def run() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path, help="authenticated GPU capture")
    parser.add_argument("approval_sha256", help="independently approved SHA-256")
    parser.add_argument("responses", type=Path)
    parser.add_argument("roots", type=Path, help="trusted NVIDIA roots PEM")
    parser.add_argument("intermediates", type=Path)
    parser.add_argument("served", type=Path, help="per-run OCSP body SHA-256 log")
    parser.add_argument("served_rims", type=Path, help="per-run RIM body SHA-256 log")
    parser.add_argument("refresh_started_unix", type=int)
    parser.add_argument("import_finished_unix", type=int)
    args = parser.parse_args()
    clock = Path(__file__).with_name("check-site-clock.sh")
    subprocess.run([clock], check=True, timeout=25)
    approval_bytes = (args.run / "approval.json").read_bytes()
    if hashlib.sha256(approval_bytes).hexdigest() != args.approval_sha256:
        raise ValueError("qualification approval digest mismatch")
    approval = json.loads(approval_bytes)
    max_age = approval["maxStatusAgeSeconds"]
    if type(max_age) is not int or max_age <= 0:
        raise ValueError("expected positive integer maxStatusAgeSeconds")
    for name, field in (
        ("policy.rego", "policySha256"),
        ("inventory.csv", "inventorySha256"),
    ):
        if (
            hashlib.sha256((args.run / name).read_bytes()).hexdigest()
            != approval[field]
        ):
            raise ValueError(f"{name} differs from approval")
    with (args.run / "inventory.csv").open() as inventory:
        rows = list(csv.reader(inventory, skipinitialspace=True))
    if len(rows) != 8 or any(
        len(row) != 5
        or any(v in ("", "N/A") for v in row)
        or not re.search(r"\bB200\b", row[2])
        for row in rows
    ):
        raise ValueError("expected eight complete B200 inventory rows")
    if any(len({row[i].lower() for row in rows}) != 8 for i in (0, 1)):
        raise ValueError("expected distinct PCI addresses and GPU UUIDs")
    sdk = (args.run / "nvattest.sha256").read_text().strip()
    if not re.fullmatch("[0-9a-f]{64}", sdk) or sdk != approval["nvattestSha256"]:
        raise ValueError("unapproved nvattest build")
    nonce = (args.run / "challenge").read_text().strip()
    if not re.fullmatch("[0-9a-f]{64}", nonce):
        raise ValueError("invalid GPU challenge")
    verdict = (args.run / "attest.json").read_bytes()
    # Recheck the exact verdict bytes whose digest appears in the report.
    identities = args.run / "ueids.json"
    inputs = ["--arg", "nonce", nonce, "--slurpfile", "expected", str(identities)]
    if json.loads(identities.read_bytes()) != approval["ueids"]:
        raise ValueError("verified assignment differs from approval")
    subprocess.run(
        ["jq", "-se", *inputs, "-f", str(Path(__file__).with_name("claims.jq"))],
        input=verdict,
        stdout=subprocess.DEVNULL,
        check=True,
        timeout=15,
    )
    rims = set(approval["rimSha256"])
    if (
        not rims
        or any(not re.fullmatch("[0-9a-f]{64}", digest) for digest in rims)
        or rims != set(args.served_rims.read_text().splitlines())
    ):
        raise ValueError("RIM bytes served during the challenge differ from approval")
    now = int(time.time())
    elapsed = args.import_finished_unix - args.refresh_started_unix
    if (
        elapsed <= 0
        or args.refresh_started_unix <= 0
        or not 0 < args.import_finished_unix <= now
    ):
        raise ValueError("need the start and end of a completed refresh")
    enrolled = approval["certificateFingerprints"]
    if (
        not isinstance(enrolled, dict)
        or not enrolled
        or len(set(enrolled.values())) != len(enrolled)
    ):
        raise ValueError("expected distinct enrolled certificate fingerprints")
    deadlines: list[tuple[int, str]] = []
    responses: dict[str, str] = {}
    for name, fingerprint in enrolled.items():
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name) or not re.fullmatch(
            r"[0-9a-f]{64}", fingerprint
        ):
            raise ValueError("invalid enrolled name or SHA-256 fingerprint")
        try:
            deadline, digest = response_deadline(
                args.responses / name,
                fingerprint,
                args.roots,
                args.intermediates,
                max_age,
                args.import_finished_unix,
            )
        except (ValueError, KeyError, OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError(f"{name}: {exc}") from exc
        deadlines.append((deadline, name))
        responses[name] = digest
    if set(responses.values()) != set(args.served.read_text().splitlines()):
        raise ValueError(
            "signed responses differ from responses served during the fresh GPU challenge"
        )
    for chain in (args.roots, args.intermediates):
        deadlines.append((min(cert_deadlines(chain.read_text())), chain.name))
    end, limiting = min(deadlines)
    # Allow for the measured clock offset and NTS round-trip bound.
    remaining = end - int(time.time()) - 2
    utc = datetime.fromtimestamp(end, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    if remaining <= elapsed:
        raise ValueError(
            f"{limiting} at {utc}: remaining validity cannot cover another measured media refresh"
        )
    fields = ("policySha256", "ueids", "certificateFingerprints", "maxStatusAgeSeconds")
    result = {field: approval[field] for field in fields}
    result.update(
        approvalSha256=args.approval_sha256,
        rimSha256=sorted(rims),
        ocspSha256=responses,
        challenge=nonce,
        gpuVerdictSha256=hashlib.sha256(verdict).hexdigest(),
        limitingObject=limiting,
        earliestExpiryUtc=utc,
        remainingSeconds=remaining,
        observedRefreshSeconds=elapsed,
        refreshStartedUnix=args.refresh_started_unix,
        importFinishedUnix=args.import_finished_unix,
    )
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        run()
    except (KeyError, TypeError, ValueError, OSError, subprocess.SubprocessError) as e:
        sys.exit(str(e))
