"""Reject an unsupported source checkout before the Cloud runner has side effects."""
from pathlib import Path
import re
import sys


def require_v2_source():
    # This early source check avoids even building/provisioning for an unsupported
    # lane. The compiled Go entry point independently checks its actual constant.
    source = Path(__file__).resolve().parents[3] / "internal/cmds/launchconfig/config.go"
    with source.open("rb") as stream:
        data = stream.read((1 << 20) + 1)
    versions = re.findall(rb'^\s*SchemaVersion\s*=\s*"([^"\r\n]+)"\s*$', data, re.MULTILINE)
    if len(data) > 1 << 20 or versions != [b"c8s-launch/v2"]:
        raise ValueError("unsupported Cloud launch schema")


if __name__ == "__main__":
    try:
        require_v2_source()
    except (OSError, ValueError):
        print("This Cloud acceptance lane requires c8s-launch/v2 and a dedicated "
              "measured CDS. Retained runs must use their original cleanup binary.",
              file=sys.stderr)
        sys.exit(1)
