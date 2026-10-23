"""Run-scoped native test resources. No image, guest role or fixture defaults."""
import json
import os
from pathlib import Path
import re
import subprocess
import time
import uuid

NS = "confai-images"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def budget(deadline=None, maximum=30):
    remaining = maximum if deadline is None else deadline - time.monotonic()
    require(remaining > 0, "phase deadline reached")
    return min(maximum, remaining)


def pause(deadline, seconds=5):
    time.sleep(min(seconds, max(0, deadline - time.monotonic())))


def write(path, value):
    data = value if isinstance(value, bytes) else (json.dumps(value, indent=2) + "\n").encode()
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def command(argv, data=None, timeout=30):
    result = subprocess.run(list(map(str, argv)), input=data, capture_output=True, timeout=timeout)
    # Do not echo argv, stdin or stderr: launch inputs and API errors can contain Secrets.
    require(result.returncode == 0, "command failed: " + Path(argv[0]).name + " (exit " + str(result.returncode) + ")")
    return result.stdout


def kube(*args, data=None, timeout=30, raw=False):
    # --request-timeout disables in-cluster credential fallback in this runner.
    body = command(["kubectl", "-n", NS, *args], data=data, timeout=timeout)
    return body if raw else json.loads(body) if body.strip() else None


class OwnedResources:
    def __init__(self, root, run, attempt, repo):
        require(re.fullmatch(r"[1-9][0-9]*", run) and re.fullmatch(r"[1-9][0-9]*", attempt), "invalid workflow identity")
        require(repo.lower() == "confidential-dot-ai/c8s", "unexpected repository")
        self.root, self.run, self.attempt, self.repo = root, run, attempt, repo
        self.name = f"c8s-podacc-{run}-{attempt}"
        self.private, self.evidence = root / "private", root / "evidence"
        for directory in (self.private, self.evidence):
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.ledger, self.nonce_file = self.private / "resources.json", self.private / "creation-nonces.json"

    def resources(self):
        return json.loads(self.ledger.read_text()) if self.ledger.exists() else []

    def metadata(self, kind, suffix):
        key = kind + ":" + suffix
        nonces = json.loads(self.nonce_file.read_text()) if self.nonce_file.exists() else {}
        if key not in nonces:
            require(not any(e["kind"] == kind and e["suffix"] == suffix for e in self.resources()), "owned resource lost creation nonce")
            nonces[key] = uuid.uuid4().hex
            write(self.nonce_file, nonces)
        return {"name": self.name + suffix, "namespace": NS,
                "labels": {"ci.confidential.ai/managed": "true", "ci.confidential.ai/resource": "pod-connected-acceptance",
                           "ci.confidential.ai/run-id": self.run, "ci.confidential.ai/run-attempt": self.attempt},
                "annotations": {"ci.confidential.ai/repo": self.repo, "ci.confidential.ai/creation-nonce": nonces[key]}}

    def owned(self, obj, kind, suffix, uid=None):
        expected, actual = self.metadata(kind, suffix), obj["metadata"]
        require(all(actual.get(k) == expected[k] for k in ("name", "namespace")), "resource scope differs")
        for field in ("labels", "annotations"):
            require(all(actual.get(field, {}).get(k) == v for k, v in expected[field].items()), "resource ownership differs")
        require(uid is None or actual["uid"] == uid, "resource UID changed")
        return obj

    def create(self, kind, suffix, spec):
        require(not any(e["kind"] == kind and e["suffix"] == suffix for e in self.resources()), "duplicate resource intent")
        require(kube("get", kind, self.name + suffix, "--ignore-not-found", "-o", "json") is None, "refusing existing resource")
        spec["metadata"] = self.metadata(kind, suffix)
        entries = self.resources()
        entry = {"kind": kind, "suffix": suffix, "uid": None}
        entries.append(entry)
        write(self.ledger, entries)
        obj = kube("create", "-f", "-", "-o", "json", data=json.dumps(spec).encode())
        self.owned(obj, kind, suffix)
        entry["uid"] = obj["metadata"]["uid"]
        write(self.ledger, entries)
        return obj

    def get(self, kind, suffix, deadline=None):
        entry = next(e for e in self.resources() if e["kind"] == kind and e["suffix"] == suffix)
        return self.owned(kube("get", kind, self.name + suffix, "-o", "json", timeout=budget(deadline)), kind, suffix, entry["uid"])

    def remove(self, kind, suffix, deadline=None):
        deadline = min(deadline or float("inf"), time.monotonic() + 120)
        entry = next(e for e in self.resources() if e["kind"] == kind and e["suffix"] == suffix)
        obj = kube("get", kind, self.name + suffix, "--ignore-not-found", "-o", "json", timeout=budget(deadline))
        if obj:
            self.owned(obj, kind, suffix, entry["uid"])
            plural = {"vm": "virtualmachines", "pod": "pods", "pvc": "persistentvolumeclaims", "secret": "secrets", "service": "services"}[kind]
            base = "/apis/kubevirt.io/v1" if kind == "vm" else "/api/v1"
            url = f"{base}/namespaces/{NS}/{plural}/{self.name}{suffix}"
            options = {"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": obj["metadata"]["uid"]}, "propagationPolicy": "Foreground"}
            kube("delete", "--raw", url, "-f", "-", data=json.dumps(options).encode(), raw=True, timeout=budget(deadline))
        while time.monotonic() < deadline:
            if kube("get", kind, self.name + suffix, "--ignore-not-found", "-o", "json", timeout=budget(deadline)) is None:
                return
            pause(deadline)
        raise RuntimeError("resource deletion did not complete: " + kind + suffix)

    def cleanup(self):
        errors, removed = [], []
        deadline = time.monotonic() + 540
        entries = list(reversed(self.resources()))
        # All VMs must disappear before any shared PVC, launch Secret or Service.
        for group in ([e for e in entries if e["kind"] == "vm"], [e for e in entries if e["kind"] != "vm"]):
            for entry in group:
                try:
                    self.remove(entry["kind"], entry["suffix"], deadline)
                    removed.append({"kind": entry["kind"], "name": self.name + entry["suffix"]})
                except Exception as error:
                    errors.append(str(error))
            if errors:
                break
        write(self.evidence / "cleanup.json", {"name": self.name, "complete": not errors, "removed": removed, "errors": errors})
        require(not errors, "cleanup incomplete; retained private ownership ledger")
