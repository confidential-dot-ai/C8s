#!/usr/bin/env python3
"""Build the pilot gateway filter or check a recording against the approved site."""

import hashlib
import ipaddress
import json
import re
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any


def firewall(config: dict[str, Any]) -> str:
    interfaces = config["interfaces"]
    if not interfaces or any(
        not re.fullmatch("[a-zA-Z0-9_.-]{1,15}", i) for i in interfaces
    ):
        raise ValueError("expected dedicated pilot ingress interfaces")
    sources = ", ".join(json.dumps(i) for i in interfaces)
    addresses = [ipaddress.ip_address(ip) for ip in config["destinations"]]
    if not addresses:
        raise ValueError("expected permitted site addresses")
    rules = ["create table inet c8s_pilot", "add counter inet c8s_pilot denied"]
    for hook in ("input", "forward"):
        rules.append(
            f"add chain inet c8s_pilot {hook} {{ type filter hook {hook} priority -10; policy accept; }}"
        )
        match = f"add rule inet c8s_pilot {hook} iifname {{ {sources} }}"
        for version, family in [(4, "ip"), (6, "ip6")]:
            allow = ", ".join(str(ip) for ip in addresses if ip.version == version)
            if allow:
                rules.append(f"{match} {family} daddr {{ {allow} }} accept")
        rules.append(
            f'{match} counter name "denied" log prefix "c8s-pilot-denied " drop'
        )
    return "\n".join(rules)


def utc(value: str) -> datetime:
    stamp = datetime.fromisoformat(value.strip())
    if stamp.utcoffset() != timedelta(0):
        raise ValueError("pilot timestamps require an explicit UTC offset")
    return stamp


def observed_refresh(config: dict[str, Any], recording: Path) -> datetime:
    witness = recording / "refresh.json"
    key = ["-pubin", "-inkey", config["refreshObserverKey"]]
    proof = ["-sigfile", str(recording / "refresh.sig"), "-rawin", "-in", str(witness)]
    subprocess.run(["openssl", "pkeyutl", "-verify", *key, *proof], check=True, timeout=15, stdout=subprocess.DEVNULL)
    event = json.loads(witness.read_bytes())
    raw = (recording / "refresh-event.log").read_bytes()
    if not raw or hashlib.sha256(raw).hexdigest() != event["eventSha256"]:
        raise ValueError("missing or mismatched source refresh event")
    if (
        event["event"] != "background-refresh-succeeded"
        or not config["pilotId"]
        or event["pilotId"] != config["pilotId"]
        or event["verifierImage"] != config["verifierImage"]
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", event["verifierImage"])
        or not re.fullmatch(r"[0-9a-f]{64}", event["snapshotSha256"])
        or type(event["generation"]) is not int
        or event["generation"] < 1
    ):
        raise ValueError("observer did not confirm a completed background refresh for the approved verifier")
    message = re.fullmatch(rb"\S+\s+INFO\s+selected_tdx: (\{[^\n]*\})\n?", raw)
    if not message:
        raise ValueError("expected a single selected_tdx service record")
    source = json.loads(message[1])
    expected = {
        "event": "selected_tdx_recheck",
        "outcome": "valid",
        "trigger": "sighup",
        "scope": "intel_collateral",
        "generation": event["generation"],
        "sha256": event["snapshotSha256"],
        "siteTime": event["observedUtc"],
    }
    if (event["scope"] != "intel_collateral" or type(source.get("generation")) is not int
            or any(source.get(field) != value for field, value in expected.items())):
        raise ValueError("source did not verify the selected Intel generation on SIGHUP")
    return utc(event["observedUtc"])


def interval(directory: Path) -> tuple[datetime, datetime]:
    return utc((directory / "start-utc").read_text()), utc((directory / "end-utc").read_text())


def audit(config: dict[str, Any], recording: Path, first: Path, final: Path) -> None:
    started, ended = interval(recording)
    pilot_start = utc((recording / "pilot-start-utc").read_text())
    first_start, first_end = interval(first)
    final_start, final_end = interval(final)
    if json.loads((recording / "network.json").read_bytes()) != config:
        raise ValueError("recorder was armed with a different pilot configuration")
    pilot_end = utc(config["pilotEndUtc"])
    if not started <= pilot_start <= first_start < first_end < final_start < final_end <= ended:
        raise ValueError("capture must cover the install and two strictly ordered workload runs")
    if final_start < pilot_end - timedelta(days=1) or final_end >= pilot_end:
        raise ValueError("the final workload run must start and finish in the pilot's final 24 hours")
    if not pilot_start <= observed_refresh(config, recording) <= first_end:
        raise ValueError("observed Intel refresh must fall between installation and the end of the first run")
    capture = (recording / "tcpdump.log").read_text()
    if "0 packets dropped by kernel" not in capture.splitlines():
        raise ValueError("missing lossless capture evidence")
    if (recording / "filter.nft").read_text() != firewall(config) + "\n":
        raise ValueError("capture filter differs from approved gateway configuration")
    if (recording / "before.nft").read_bytes() != (recording / "after.nft").read_bytes():
        raise ValueError("gateway filter changed during the recording")
    stats = json.loads((recording / "counter.json").read_text())
    counters = [
        r["counter"]["packets"]
        for r in stats["nftables"]
        if r.get("counter", {}).get("name") == "denied"
        and r["counter"]["table"] == "c8s_pilot"
        and r["counter"]["family"] == "inet"
    ]
    if counters != [0] or (recording / "denied.log").stat().st_size:
        raise ValueError("gateway observed denied egress, or its counter is missing")
    roles = config["sources"]
    if set(roles) != {"host", "ta", "worker", "cli"} or any(
        not ips for ips in roles.values()
    ):
        raise ValueError("specify pre-NAT source addresses for host, ta, worker and cli")
    by_ip = {
        str(ipaddress.ip_address(ip)): role for role, ips in roles.items() for ip in ips
    }
    if len(by_ip) != sum(map(len, roles.values())):
        raise ValueError("source addresses must distinguish all four observers")
    names = {name.lower().rstrip(".") for name in config["dnsNames"]}
    indices = {
        link["ifname"]: str(link["ifindex"])
        for link in json.loads((recording / "interfaces.json").read_bytes())
    }
    ingress = {indices[name] for name in config["interfaces"]}
    observed: set[str] = set()
    fields = ["sll.ifindex", "ip.src", "ipv6.src", "dns.qry.name"]
    args = ["tshark", "-n", "-r", str(recording / "dns.pcap")]
    args.extend(["-Y", "dns.flags.response == 0", "-T", "fields"])
    for field in fields:
        args.extend(["-e", field])
    with subprocess.Popen(args, stdout=subprocess.PIPE, text=True) as proc:
        assert proc.stdout is not None
        for row in proc.stdout:
            index, v4, v6, queries = row.rstrip("\n").split("\t")
            if index not in ingress:
                continue
            role = by_ip.get(v4 or v6)
            if not role:
                raise ValueError(f"unexpected DNS client {v4 or v6} on pilot ingress")
            for query in queries.split(","):
                if query.lower().rstrip(".") not in names:
                    raise ValueError(f"{role} queried an unapproved DNS name {query!r}")
            observed.add(role)
        if proc.wait() != 0:
            raise ValueError("tshark failed to decode the recording")
    if observed != set(roles):
        raise ValueError(f"missing DNS observations from {sorted(set(roles) - observed)}")
    print(f"Pilot started {pilot_start.isoformat()}. Recording covers both run intervals and the witnessed Intel refresh.")
    print("Observed approved DNS from all four sources and zero denied packets throughout the capture.")


if __name__ == "__main__":
    try:
        config = json.loads(Path(sys.argv[2]).read_text())
        if sys.argv[1] == "firewall" and len(sys.argv) == 3:
            if utc(config["pilotEndUtc"]) <= datetime.now(UTC):
                raise ValueError("approve a future UTC pilot end before arming the gateway")
            print(firewall(config))
        elif sys.argv[1] == "audit" and len(sys.argv) == 6:
            audit(config, Path(sys.argv[3]), Path(sys.argv[4]), Path(sys.argv[5]))
        else:
            raise ValueError("use firewall CONFIG or audit CONFIG RECORDING FIRST_RUN FINAL_RUN")
    except (ValueError, OSError, TypeError, IndexError, KeyError, subprocess.SubprocessError) as error:
        sys.exit(str(error))
