"""Attestation evidence for the backends' evidence functions.

  evidence.py body <report-data-hex>
      the local attestation service's request body over the report data
  evidence.py unsigned
      the {platform, evidence} envelope on stdin with one byte of its signed
      report body changed, its launch measurement: an SNP report's
      MEASUREMENT, or a TDX quote's MRTD (after the 48-byte header, and in a
      v5 quote the 6-byte body descriptor); exit 77 for any other shape
  evidence.py mock <url> <report-data-hex> [<launch-digest-hex>]
      the kind mock's evidence over the report data; with a digest, the
      mock's version-2 SNP report reporting it instead (the mock checks no
      signature, and its verifier reads the digest from the report it is shown)
"""
import base64
import json
import sys
import urllib.request

UNSUPPORTED = 77


def b64(data):
    return base64.b64encode(bytes(data)).decode()


def body(report_data):
    return json.dumps({"report_data": b64(bytes.fromhex(report_data))})


def unsigned(env):
    ev = env.get("evidence") or {}
    if "attestation_report" in ev:
        key, offset = "attestation_report", 0x90
    elif "quote" in ev:
        key = "quote"
    else:
        sys.exit(UNSUPPORTED)
    blob = bytearray(base64.b64decode(ev[key]))
    if key == "quote":
        version = int.from_bytes(blob[0:2], "little")
        if version not in (4, 5):
            sys.exit(UNSUPPORTED)
        offset = 48 + (6 if version == 5 else 0) + 136
    blob[offset] ^= 0xFF
    ev[key] = b64(blob)
    return json.dumps(env)


def mock(url, report_data, digest=""):
    if not digest:
        req = urllib.request.Request(url + "/attest", body(report_data).encode(),
                                     {"Content-Type": "application/json"})
        return urllib.request.urlopen(req, timeout=20).read().decode()
    report = bytearray(1184)
    report[0] = 0x02     # report version 2
    report[0x0A] = 0x03  # SMT-allowed policy
    rd = bytes.fromhex(report_data)
    report[0x50:0x50 + len(rd)] = rd
    d = bytes.fromhex(digest)
    report[0x90:0x90 + len(d)] = d
    return json.dumps({"platform": "snp", "evidence": {"attestation_report": b64(report)}})


if __name__ == "__main__":
    cmd, args = sys.argv[1], sys.argv[2:]
    if cmd == "body":
        print(body(*args))
    elif cmd == "unsigned":
        print(unsigned(json.load(sys.stdin)))
    elif cmd == "mock":
        sys.stdout.write(mock(*args))
    else:
        sys.exit(f"evidence.py: no command {cmd!r}")
