#!/usr/bin/env python3
"""Owned, development-image runtime observations; never production acceptance."""
import base64
import importlib.util
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import time
import uuid

from tdx_pod_resources import NS, budget, kube, pause, require, write

spec = importlib.util.spec_from_file_location("pod_acceptance", Path(__file__).with_name("tdx-pod-acceptance.py"))
acceptance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acceptance)

WRAPPER = "bypassed-by-60-dev-runc.toml"
MAX_TRANSCRIPT = 262144
UNITS = ("rke2-role.service", "nri-node-ip.service", "containerd-data-disk.service", "podcvm-containerd.service", "podcvm-kubelet.service", "podcvm-status.service")
# Journal records matching these patterns are omitted entirely, never partially exposed.
SENSITIVE = re.compile(r"private.?key|-----BEGIN|secret|password|passwd|token|authorization|bearer|credential|kubeconfig|launch\.yaml|\benv(?:ironment|s)?\b|config\s*[=:]", re.I)
JOURNAL_PROJECTION = ('select((.MESSAGE|tostring|test(' + json.dumps(SENSITIVE.pattern) + ';"i"))|not) | '
                      '{kind:"journal",unit:._SYSTEMD_UNIT,time:.__REALTIME_TIMESTAMP,message:(.MESSAGE|tostring|.[0:1536])}')
EXPECT = r'''log_user 1
set timeout 30
spawn virtctl --kubeconfig $env(C8S_DIAG_KUBECONFIG) -n $env(C8S_DIAG_NS) console $env(C8S_DIAG_VM)
expect {
    -re {Successfully connected} {}
    timeout {exit 11}
    eof {exit 12}
}
send -- "\r"
expect {
    -re {# ?$} {}
    timeout {exit 13}
    eof {exit 14}
}
send -- "$env(C8S_DIAG_COMMAND)\r"
set timeout 90
expect {
    -re "\r?\n$env(C8S_DIAG_END)\r?\n" {}
    timeout {exit 15}
    eof {exit 16}
}
send -- "\x1d"
exit 0
'''


def public_failure(error):
    # Only our static failure vocabulary is publishable; arbitrary exception text is private.
    safe = {"missing scoped VMI console authority", "missing native runner credentials",
            "owned diagnostic VMI is not running", "diagnostic VMI replaced during console",
            "console timed out", "console output exceeded byte limit", "console frame missing or duplicated",
            "console frame order differs", "console command receipts incomplete", "phase deadline reached",
            "VMI owner differs", "VMI replaced during acceptance", "resource ownership differs", "resource UID changed",
            "production root import failed", "production root import timed out", "TDX capacity binder did not schedule",
            "three owned TDX VMIs did not reach Running", "owned Pod runtime capture incomplete"}
    message = str(error) if type(error) is RuntimeError else ""
    if message not in safe and not re.fullmatch(r"console driver exit -?[0-9]+|command failed: (?:kubectl|python3) \(exit -?[0-9]+\)", message):
        message = "details withheld; inspect private runner state"
    return {"errorClass": type(error).__name__, "error": message}


def validate_diagnostic_pins(pins):
    acceptance.validate_pin_structure(pins)
    require(pins.get("diagnosticOnly") is True and pins.get("developmentProfile") is True,
            "runtime diagnostics require explicit development-only pins")
    require(pins.get("runtimeWrapper") == WRAPPER, "development wrapper bypass must be declared")


def console_payload(marker):
    require(re.fullmatch(r"[0-9a-f]{32}", marker), "invalid console frame")
    units = " ".join(UNITS)
    # Each command emits only a fixed projection. No inspect, environment, launch or key reads.
    return f'''export HISTFILE=/dev/null
set +e
set -o pipefail
printf '__C8S_%s_BEGIN__\\n' '{marker}'
timeout 10 systemctl show --no-pager -p Id -p LoadState -p ActiveState -p SubState -p Result -p ExecMainCode -p ExecMainStatus {units} 2>/dev/null | jq -cRs '{{kind:"units",text:.}}'
printf '{{"kind":"command","name":"units","exit":%s}}\\n' "$?"
timeout 15 journalctl -b --no-pager -o json -n 160 {' '.join('-u '+unit for unit in UNITS)} 2>/dev/null | jq -c '{JOURNAL_PROJECTION}'
printf '{{"kind":"command","name":"journal","exit":%s}}\\n' "$?"
timeout 15 /usr/lib/c8s/pod-runtime/bin/crictl --runtime-endpoint unix:///run/k3s/containerd/containerd.sock pods -o json 2>/dev/null | jq -c '.items[]?|{{kind:"sandbox",id:.id,name:.metadata.name,state:.state,createdAt:.createdAt}}'
printf '{{"kind":"command","name":"sandboxes","exit":%s}}\\n' "$?"
timeout 15 /usr/lib/c8s/pod-runtime/bin/crictl --runtime-endpoint unix:///run/k3s/containerd/containerd.sock ps -a -o json 2>/dev/null | jq -c '.containers[]?|{{kind:"container",id:.id,name:.metadata.name,state:.state,imageRef:.imageRef,createdAt:.createdAt}}'
printf '{{"kind":"command","name":"containers","exit":%s}}\\n' "$?"
timeout 10 /usr/lib/c8s/pod-runtime/bin/ctr --address /run/k3s/containerd/containerd.sock plugins ls 2>/dev/null | head -70 | jq -cRs '{{kind:"plugins",text:.}}'
printf '{{"kind":"command","name":"plugins","exit":%s}}\\n' "$?"
printf '__C8S_%s_END__\\n' '{marker}'
'''


def public_records(raw, marker):
    require(len(raw) <= MAX_TRANSCRIPT, "oversized console transcript")
    lines = raw.decode(errors="replace").replace("\r", "").splitlines()
    start, end = "__C8S_" + marker + "_BEGIN__", "__C8S_" + marker + "_END__"
    require(lines.count(start) == 1 and lines.count(end) == 1, "console frame missing or duplicated")
    a, b = lines.index(start), lines.index(end)
    require(a < b, "console frame order differs")
    records, omitted = [], 0
    fields = {"units": {"kind", "text"}, "journal": {"kind", "unit", "time", "message"},
              "sandbox": {"kind", "id", "name", "state", "createdAt"},
              "container": {"kind", "id", "name", "state", "imageRef", "createdAt"},
              "plugins": {"kind", "text"}, "command": {"kind", "name", "exit"}}
    for line in lines[a+1:b]:
        try:
            record = json.loads(line)
        except ValueError:
            # Interleaved boot logs, shell prompts, and command echoes are not evidence.
            omitted += 1
            continue
        if not isinstance(record, dict) or record.get("kind") not in fields or set(record) != fields[record["kind"]]:
            omitted += 1
            continue
        if record["kind"] == "journal" and record.get("unit") not in UNITS:
            omitted += 1
            continue
        if any(value is not None and type(value) not in (str, int) for value in record.values()):
            omitted += 1
            continue
        encoded = json.dumps(record)
        if len(encoded) > 16384 or SENSITIVE.search(encoded):
            omitted += 1
            continue
        records.append(record)
    completed = {r["name"] for r in records if r["kind"] == "command" and type(r["exit"]) is int}
    require(completed == {"units", "journal", "sandboxes", "containers", "plugins"}, "console command receipts incomplete")
    return {"records": records, "omittedRecords": omitted}


def bounded_process(argv, env, deadline):
    """Read a PTY driver's pipe with byte/time limits; kill only this process group."""
    raw = bytearray()
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, env=env, start_new_session=True)
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return bytes(raw), "console timed out"
                if not selector.select(min(remaining, 1)):
                    continue
                block = os.read(process.stdout.fileno(), min(8192, MAX_TRANSCRIPT + 1 - len(raw)))
                if not block:
                    code = process.wait(timeout=budget(deadline, 5))
                    return bytes(raw), None if code == 0 else "console driver exit " + str(code)
                raw.extend(block)
                if len(raw) > MAX_TRANSCRIPT:
                    return bytes(raw[:MAX_TRANSCRIPT]), "console output exceeded byte limit"
    finally:
        # expect may exit before virtctl; terminate the whole owned session even then.
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            pass
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=3)
        process.stdout.close()


class RuntimeDiagnostic(acceptance.Acceptance):
    def __init__(self, *args, pins=None):
        super().__init__(*args)
        self.name = f"c8s-poddebug-{self.run}-{self.attempt}"
        self.pins = pins if pins is not None else json.loads((acceptance.FIXTURE / "development-image.json").read_text())
        self.run_deadline = time.monotonic() + 53 * 60

    def metadata(self, kind, suffix):
        result = super().metadata(kind, suffix)
        result["labels"]["ci.confidential.ai/resource"] = "pod-runtime-diagnostic"
        return result

    def validate_image(self, raw=None):
        validate_diagnostic_pins(self.pins)
        if raw is not None:
            return acceptance.validate_manifest_structure(raw, self.pins)

    def prepare(self):
        self.validate_image()
        require(kube("auth", "can-i", "get", "virtualmachineinstances.subresources.kubevirt.io", "--subresource=console", raw=True).strip() == b"yes", "missing scoped VMI console authority")
        # tokenFile avoids copying or exposing the in-cluster service-account token.
        service_account = Path("/var/run/secrets/kubernetes.io/serviceaccount")
        require(all((service_account / name).is_file() for name in ("ca.crt", "token")), "missing native runner credentials")
        write(self.private / "console-kubeconfig.json", {"apiVersion": "v1", "kind": "Config", "current-context": "owned",
            "clusters": [{"name": "native", "cluster": {"server": "https://kubernetes.default.svc", "certificate-authority": str(service_account / "ca.crt")}}],
            "users": [{"name": "runner", "user": {"tokenFile": str(service_account / "token")}}],
            "contexts": [{"name": "owned", "context": {"cluster": "native", "user": "runner", "namespace": NS}}]})
        write(self.private / "console.exp", EXPECT.encode())
        super().prepare()
        write(self.evidence / "diagnostic-scope.json", self.scope())

    def scope(self):
        return {"diagnosticOnly": True, "productionAcceptance": False, "developmentProfile": True,
                "runtimeWrapper": WRAPPER, "limitation": "The development image bypasses c8s-runc; a successful boot does not establish production boot or acceptance."}

    def console(self, side):
        require(side in ("a", "b"), "only owned Pod consoles are observable")
        deadline = self.deadline(165)
        before = self.instance(side, deadline)
        require(before.get("status", {}).get("phase") == "Running", "owned diagnostic VMI is not running")
        uid = before["metadata"]["uid"]
        marker = uuid.uuid4().hex
        payload = base64.b64encode(console_payload(marker).encode()).decode()
        env = {"PATH": os.environ["PATH"], "TERM": "dumb", "C8S_DIAG_NS": NS,
               "C8S_DIAG_VM": self.name + "-" + side, "C8S_DIAG_KUBECONFIG": str(self.private / "console-kubeconfig.json"),
               "C8S_DIAG_COMMAND": "printf '%s' '" + payload + "' | base64 -d | /bin/bash", "C8S_DIAG_END": "__C8S_" + marker + "_END__"}
        require(len(env["C8S_DIAG_COMMAND"].encode()) < 3500, "console command exceeds canonical PTY budget")
        raw, error = bounded_process(["expect", str(self.private / "console.exp")], env, min(deadline - 15, time.monotonic() + 140))
        write(self.private / (side + "-console.raw"), raw)
        # Revalidate the persisted VM UID and held VMI UID before publishing any observation.
        after = self.instance(side, deadline)
        require(after.get("metadata", {}).get("uid") == uid, "diagnostic VMI replaced during console")
        write(self.evidence / (side + "-console-status.json"), {**self.scope(), "vmiUID": uid, "driverError": error})
        require(error is None, error or "console failed")
        report = {**self.scope(), "vmiUID": uid, **public_records(raw, marker)}
        write(self.evidence / (side + "-runtime.json"), report)
        return report

    def diagnose(self):
        # An attested status still describes this dev image; it is not a production receipt.
        for side in acceptance.SIDES:
            self.connect(side, 30808 if side == "server" else 8443)
        deadline = self.deadline(300)
        for _ in range(3):
            if time.monotonic() >= deadline:
                break
            try:
                self.ca(self.evidence / "mesh-ca.pem", deadline)
            except (RuntimeError, OSError, ValueError) as error:
                self.observation_error("cds-ca", "server", error)
            for side in ("a", "b"):
                for mode, label in ((["pod-status", "get"], "status"), (["pod-attest"], "attestation")):
                    try:
                        report = self.cli_read(side, mode, deadline, exact_digests=False)
                        write(self.evidence / (side + "-diagnostic-" + label + ".json"), {**self.scope(), "report": report})
                    except (RuntimeError, OSError, ValueError) as error:
                        self.observation_error("pod-status" if label == "status" else "pod-attest-observed", side, error)
            pause(deadline, 20)
        failures = {}
        for side in ("a", "b"):
            acceptance.progress("guest-runtime", side)
            try:
                self.console(side)
                acceptance.progress("guest-runtime", side, "complete")
            except Exception as error:
                failures[side] = public_failure(error)
                acceptance.progress("guest-runtime", side, "failed", **failures[side])
        write(self.evidence / "result.json", {**self.scope(), "captureComplete": not failures, "consoleFailures": failures})
        require(not failures, "owned Pod runtime capture incomplete")

    def capture(self):
        # Do not call Acceptance.capture: raw dev serial output must stay private.
        deadline = time.monotonic() + 60
        for side in acceptance.SIDES:
            if not any(item["kind"] == "vm" and item["suffix"] == "-" + side for item in self.resources()):
                continue
            try:
                vm = self.get("vm", "-" + side, deadline)
                vmi = self.instance(side, deadline)
                record = {**self.scope(), "vmUID": vm["metadata"]["uid"], "vmStatus": vm.get("status", {}),
                          "vmiUID": vmi.get("metadata", {}).get("uid"), "vmiStatus": vmi.get("status", {})}
                require(len(json.dumps(record)) <= 32768, "oversized diagnostic VM status")
                write(self.evidence / (side + "-native-status.json"), record)
            except Exception as error:
                write(self.evidence / (side + "-capture-error.json"), public_failure(error))


def run(task):
    require(not task.resources(), "runtime diagnostic already owns resources")
    try:
        for phase, action in (("prepare", task.prepare), ("provision", task.provision), ("diagnose", task.diagnose)):
            acceptance.progress(phase)
            action()
            acceptance.progress(phase, status="complete")
    except BaseException as error:
        write(task.evidence / "failure.json", {**task.scope(), "phase": phase, **public_failure(error)})
        raise RuntimeError("development runtime diagnostic failed; see bounded evidence") from None
    finally:
        for action, phase in ((task.capture, "capture"), (task.stop_forwards, "forward-cleanup")):
            try:
                action()
            except Exception as error:
                write(task.evidence / (phase + "-error.json"), public_failure(error))


def main():
    os.umask(0o077)
    require(len(sys.argv) == 2 and sys.argv[1] in ("run", "cleanup"), "expected run or cleanup")
    task = RuntimeDiagnostic(Path(os.environ["RUNNER_TEMP"]) / "pod-runtime-diagnostic", os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_RUN_ATTEMPT"], os.environ["GITHUB_REPOSITORY"])
    if sys.argv[1] == "cleanup":
        task.cleanup()
        return
    run(task)
    print("Development runtime diagnostics captured; production acceptance remains unverified.")


if __name__ == "__main__":
    main()
