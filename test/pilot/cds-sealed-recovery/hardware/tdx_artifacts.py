"""Independent native TDX artifact and owned fixture validation."""
import json
from pathlib import Path
import re
from run import need,digest,resource_path,LABEL,check_probe_network_policy

def image_inputs(directory):
    p = Path(directory)
    m = json.loads((p / "manifest.json").read_text())
    need(m["version"] == 3 and m["build"]["platform"] == "tdx" and m["build"]["memory"] == "4G", "TDX 4G manifest v3 required")
    pins = m["tdx"]
    need(all(re.fullmatch(r"[0-9a-f]{96}", pins[k]) and set(pins[k]) != {"0"} for k in ("mrtd", "rtmr1", "rtmr2")), "complete independent TDX image pins required")
    entries = [(m["outputs"]["disk_image"], "disk.raw"), (m["outputs"]["uki"], "uki.efi"), (pins["firmware"], "OVMF.tdx.fd")]
    for entry, name in entries:
        need(entry["path"] == name and digest(p / name) == entry["sha256"], "artifact hash mismatch: " + name)
    need((p / "disk.raw").stat().st_size < 8*1024**3, "root disk exceeds owned claim")
    return pins, {name: e["sha256"] for e, name in entries}


def check_fixture(items, run, node, uid):
    need(len(items) == 5 and sorted(i["kind"] for i in items) == ["NetworkPolicy", "PersistentVolumeClaim", "Pod", "Secret", "VirtualMachine"], "unexpected TDX fixture resources")
    for item in items:
        resource_path(item)
        need(item["metadata"]["labels"][LABEL] == run, "mixed fixture ownership")
    vm = next(i for i in items if i["kind"] == "VirtualMachine")
    spec = vm["spec"]["template"]["spec"]
    selector = spec["nodeSelector"]
    need(selector.get("kubernetes.io/hostname") == node and selector.get("cloud.confidential.ai.node-restriction.kubernetes.io/node-uid") == uid, "worker identity must be pinned")
    need(vm["spec"]["runStrategy"] == "Manual" and spec["domain"].get("launchSecurity") == {"tdx": {}}, "manual native TDX guest required")
    need(not any("cloudInit" in json.dumps(v) for v in spec.get("volumes", [])), "cloud-init is forbidden")
    policy = next(i for i in items if i["kind"] == "NetworkPolicy")
    check_probe_network_policy(policy, run)
    need(all(vm["spec"]["template"]["metadata"]["labels"].get(k) == v for k, v in policy["spec"]["podSelector"]["matchLabels"].items()), "network policy does not select the owned guest")
    return vm
