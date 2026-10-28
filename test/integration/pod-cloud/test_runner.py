"""Run the actual live-lane shell driver against local process doubles only."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest


RUNNER = Path(__file__).with_name("run.sh")
ASSERTIONS = [
    "attestedReadiness", "cleanup", "exactDigests", "meshDNSInternet",
    "negativeProbes", "normalScheduler", "providerDeletion", "readinessCycle",
    "restartRecovery", "timedRenewal",
]
TIMEOUT_ASSERTIONS = [
    "attestedReadiness", "cleanup", "exactDigests", "lateVerifiedResultRejected",
    "normalScheduler", "persistedVerificationDeadline", "providerDeletion",
    "readinessWithdrawn", "restartRecovery", "timeoutTermination",
]
PROVIDER_SOURCE = "1" * 40
DOUBLE = r'''#!/usr/bin/env python3
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

tool, args = Path(sys.argv[0]).name, sys.argv[1:]
root = Path(os.environ["PODCLOUD_DOUBLE_ROOT"])
node = root / "node.json"
with (root / "calls.jsonl").open("a") as stream:
    stream.write(json.dumps([tool, *args]) + "\n")
def option(name):
    return args[args.index(name) + 1]
def save(path, value):
    path.write_text(json.dumps(value))
if tool == "timeout":
    os.execvp(args[1], args[1:])
elif tool == "git":
    if args == ["rev-parse", "--verify", "HEAD"]:
        print("1" * 40)
    elif args == ["status", "--porcelain=v1", "--untracked-files=normal"]:
        if os.environ.get("PODCLOUD_DIRTY") == "1":
            print(" M internal/podprovider/provider.go")
    else:
        raise SystemExit("unexpected git command")
elif tool == "go":
    runner = Path(option("-o"))
    runner.write_text("offline runner double")
    runner.chmod(0o700)
elif tool == "kind":
    if args[:2] == ["get", "clusters"]:
        pass
    elif args[:2] == ["create", "cluster"]:
        state = Path(json.loads(Path(option("--config")).read_text())["nodes"][0]["extraMounts"][0]["hostPath"])
        cluster = option("--name")
        save(node, [{"Id": "a" * 64, "Image": "sha256:" + "b" * 64,
            "Created": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.123456Z"),
            "Config": {"Image": option("--image"), "Labels": {
                "io.x-k8s.kind.cluster": cluster, "io.x-k8s.kind.role": "control-plane"}},
            "Mounts": [{"Type": "bind", "Source": str(state), "Destination": "/podcloud", "RW": True}]}])
        Path(option("--kubeconfig")).write_text("private fixture kubeconfig")
        if os.environ.get("PODCLOUD_SCENARIO") == "partial":
            sys.exit(9)
    elif args[:2] == ["delete", "cluster"]:
        node.unlink()
    else:
        raise SystemExit("unexpected kind command")
elif tool == "docker":
    if args[0] == "version":
        print("amd64")
    elif args[0] == "inspect":
        if not node.exists():
            sys.exit(1)
        print(node.read_text())
    elif args[0] == "ps":
        if node.exists():
            print(json.loads(node.read_text())[0]["Id"])
    elif args[0] == "exec":
        state = Path(json.loads(node.read_text())[0]["Mounts"][0]["Source"])
        scenario = os.environ.get("PODCLOUD_SCENARIO", "pass")
        if "/bin/sh" in args:
            # Execute the actual mount probe against the daemon's simulated
            # filesystem view, which may differ despite matching inspect data.
            visible = state
            if scenario in ("empty-mount", "wrong-mount", "wrong-runner"):
                visible = root / (state.name + "-daemon-view")
                visible.mkdir()
                if scenario != "empty-mount":
                    shutil.copy2(state / "provider.test", visible / "provider.test")
                    shutil.copy2(state / ".mount-nonce", visible / ".mount-nonce")
                    if scenario == "wrong-mount":
                        (visible / ".mount-nonce").write_text("another invocation\n")
                    else:
                        (visible / "provider.test").write_text("different runner")
            script = args[args.index("-ec") + 1].replace("/podcloud/", str(visible) + "/")
            result = subprocess.run(["/bin/sh", "-ec", script], capture_output=True, check=False)
            # Keep the displayed checksum filename in its container namespace.
            sys.stdout.buffer.write(result.stdout.replace(os.fsencode(visible), b"/podcloud"))
            sys.stderr.buffer.write(result.stderr)
            sys.exit(result.returncode)
        if "^TestPodProviderCloudLocalCleanup$" in args:
            if scenario == "orphan-busy":
                sys.exit(8)
            save(state / "closed-before-ledger.json", {"localCleanup": True})
            sys.exit(0)
        if scenario == "orphan":
            sys.exit(9)
        if scenario == "blocked":
            (root / "exec-paused").touch()
            until = time.monotonic() + 10
            while not (root / "release-exec").exists():
                if time.monotonic() >= until:
                    sys.exit(10)
                time.sleep(0.01)
        cfg = json.loads((state / "config.json").read_text())
        save(state / "ledger.json", {"complete": True, "run": "owned-invocation"})
        if scenario != "missing":
            result = {k: cfg[k] for k in ["source", "image", "cdsImage", "cliSHA256", "manifestDigest", "meshImage"]}
            requested = cfg.get("scenario") or "connected"
            assertions = json.loads(os.environ["PODCLOUD_ASSERTIONS"])[requested]
            result.update(passed=True, run="owned-invocation", scenario=requested,
                          providerBinarySHA256=hashlib.sha256((state / "provider.test").read_bytes()).hexdigest(),
                          assertions={k: True for k in assertions})
            other = "verification-timeout" if requested == "connected" else "connected"
            if scenario == "wrong-scenario":
                result["scenario"] = other
                result["assertions"] = {k: True for k in json.loads(os.environ["PODCLOUD_ASSERTIONS"])[other]}
            if scenario == "wrong-assertions":
                result["assertions"] = {k: True for k in json.loads(os.environ["PODCLOUD_ASSERTIONS"])[other]}
            if scenario == "missing-scenario":
                del result["scenario"]
            if scenario == "missing-proof":
                del result["assertions"][assertions[-1]]
            if scenario == "false-proof":
                result["assertions"][assertions[-1]] = False
            if scenario == "extra-proof":
                result["assertions"]["unrequested"] = True
            if scenario == "wrong-binary":
                result["providerBinarySHA256"] = "f" * 64
            if scenario == "missing-binary":
                del result["providerBinarySHA256"]
            if scenario == "changed-binary":
                (state / "provider.test").write_text("replacement after execution")
            if scenario == "wrong-build":
                build = json.loads((state / "provider-build.json").read_text())
                build["providerBinarySHA256"] = "f" * 64
                save(state / "provider-build.json", build)
            if scenario == "stale":
                result["run"] = "different-invocation"
            if scenario == "cleanup-only":
                result["assertions"] = {"cleanup": True}
            if scenario == "wrong-source":
                result["source"] = "f" * 40
            save(state / "result.json", result)
    else:
        raise SystemExit("unexpected Docker command: " + args[0])
else:
    raise SystemExit("unexpected tool")
'''


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(shutil.which("jq"), "jq is required for runner tests")
        self.tmp = tempfile.TemporaryDirectory(prefix="podcloud-runner-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for tool in ("docker", "kind", "go", "git", "timeout"):
            path = self.bin / tool
            path.write_text(DOUBLE)
            path.chmod(0o700)
        self.normal_kubeconfig = self.root / "user-kubeconfig"
        self.normal_kubeconfig.write_text("user context must stay unchanged")
        self.config = {
            "source": "a" * 40, "image": "c8s-pod@2026.10.27-1",
            "cdsImage": "c8s-pod-cds@2026.10.27-1", "cliSHA256": "b" * 64,
            "manifestDigest": "sha256:" + "c" * 64,
            "meshImage": "example.invalid/mesh@sha256:" + "d" * 64,
        }
        for key in ("tokenFile", "manifestFile", "cliFile", "probeFile"):
            path = self.root / key
            path.write_text("offline fixture")
            self.config[key] = str(path)
        self.input = self.root / "input.json"
        self.input.write_text(json.dumps(self.config))
        self.state = self.root / "run"
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
                        C8S_PODCLOUD_LIVE="1", KUBECONFIG=str(self.normal_kubeconfig),
                        PODCLOUD_DOUBLE_ROOT=str(self.root), PODCLOUD_DIRTY="0",
                        PODCLOUD_ASSERTIONS=json.dumps({"connected": ASSERTIONS,
                                                       "verification-timeout": TIMEOUT_ASSERTIONS}))

    def run_driver(self, mode="run", scenario="pass"):
        args = ["bash", str(RUNNER), mode]
        if mode == "run":
            args.append(str(self.input))
        args.append(str(self.state))
        return subprocess.run(args, env=dict(self.env, PODCLOUD_SCENARIO=scenario),
                              capture_output=True, text=True, timeout=20, check=False)

    def calls(self):
        return [json.loads(line) for line in (self.root / "calls.jsonl").read_text().splitlines()]

    def test_complete_receipt_and_private_kubeconfig(self):
        result = self.run_driver()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.root / "node.json").exists())
        for call in self.calls():
            if call[:2] in (["kind", "create"], ["kind", "delete"]):
                self.assertEqual(call[call.index("--kubeconfig") + 1], str(self.state / "kubeconfig"))
            if call[:2] == ["docker", "exec"]:
                self.assertIn("a" * 64, call)
        self.assertEqual(self.normal_kubeconfig.read_text(), "user context must stay unchanged")

    def test_resolved_scenarios_and_provider_build_provenance(self):
        for scenario in (None, "", "connected", "verification-timeout"):
            for dirty in (False, True):
                with self.subTest(scenario=scenario, dirty=dirty):
                    self.state = self.root / (str(scenario) + str(dirty))
                    self.config["scenario"] = scenario
                    self.input.write_text(json.dumps(self.config))
                    self.env["PODCLOUD_DIRTY"] = "1" if dirty else "0"
                    result = self.run_driver()
                    self.assertEqual(result.returncode, 0, result.stderr)
                    receipt = json.loads((self.state / "result.json").read_text())
                    build = json.loads((self.state / "provider-build.json").read_text())
                    self.assertEqual(receipt["scenario"], scenario or "connected")
                    self.assertEqual(receipt["source"], self.config["source"])
                    self.assertEqual(build, {"source": PROVIDER_SOURCE, "dirty": dirty,
                        "providerBinarySHA256": hashlib.sha256((self.state / "provider.test").read_bytes()).hexdigest()})
                    self.assertEqual(receipt["providerBinarySHA256"], build["providerBinarySHA256"])
                    expected = TIMEOUT_ASSERTIONS if scenario == "verification-timeout" else ASSERTIONS
                    self.assertEqual(receipt["assertions"], {key: True for key in expected})

    def test_invalid_scenario_is_rejected_before_build_or_provisioning(self):
        for index, scenario in enumerate(("typo", "CONNECTED", " connected", False, True, 1, [], {})):
            with self.subTest(scenario=scenario):
                self.state = self.root / str(index)
                self.config["scenario"] = scenario
                self.input.write_text(json.dumps(self.config))
                result = self.run_driver()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("scenario must be connected or verification-timeout", result.stderr)
                self.assertFalse((self.root / "calls.jsonl").exists())
                self.assertFalse((self.state / "execution-started").exists())

    def test_scenario_assertions_and_binary_provenance_must_match(self):
        for requested in ("connected", "verification-timeout"):
            self.config["scenario"] = requested
            self.input.write_text(json.dumps(self.config))
            for scenario in ("wrong-scenario", "missing-scenario", "wrong-assertions", "missing-proof",
                             "false-proof", "extra-proof", "wrong-binary", "missing-binary",
                             "changed-binary", "wrong-build"):
                with self.subTest(requested=requested, scenario=scenario):
                    self.state = self.root / (requested + "-" + scenario)
                    result = self.run_driver(scenario=scenario)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("Missing matching complete acceptance receipt", result.stderr)
                    self.assertTrue((self.root / "node.json").exists())

    def test_historic_cleanup_does_not_require_scenario_or_provider_provenance(self):
        result = self.run_driver(scenario="missing")
        self.assertNotEqual(result.returncode, 0)
        config = json.loads((self.state / "config.json").read_text())
        del config["scenario"]
        (self.state / "config.json").write_text(json.dumps(config))
        (self.state / "provider-build.json").unlink()
        result = self.run_driver("cleanup")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.root / "node.json").exists())

    def test_partial_creation_cleanup_is_local_only(self):
        result = self.run_driver(scenario="partial")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.state / "ledger.json").exists())
        result = self.run_driver("cleanup")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.root / "node.json").exists())
        self.assertFalse(any(call[:2] in (["docker", "exec"], ["docker", "run"]) for call in self.calls()))

    def test_mount_proof_refuses_empty_or_different_state_before_execution(self):
        for scenario in ("empty-mount", "wrong-mount", "wrong-runner"):
            with self.subTest(scenario=scenario):
                self.state = self.root / scenario
                result = self.run_driver(scenario=scenario)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Docker cannot see the exact host state and runner", result.stderr)
                for marker in ("execution-started", "ledger.json", "cloud-authority-issued.json"):
                    self.assertFalse((self.state / marker).exists(), marker)
                live_calls = [call for call in self.calls() if call[:2] == ["docker", "exec"]
                              and "/bin/sh" not in call]
                self.assertEqual(live_calls, [])
                before = len(self.calls())
                result = self.run_driver("cleanup")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse((self.root / "node.json").exists())
                self.assertFalse(any(call[:2] in (["docker", "exec"], ["docker", "run"])
                                     for call in self.calls()[before:]))

    def test_missing_or_incomplete_acceptance_never_passes(self):
        for scenario in ("missing", "stale", "cleanup-only", "wrong-source"):
            with self.subTest(scenario=scenario):
                self.state = self.root / scenario
                result = self.run_driver(scenario=scenario)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Missing matching complete acceptance receipt", result.stderr)
                self.assertTrue((self.root / "node.json").exists())

    def test_replacement_container_or_mount_refuses_exec_and_delete(self):
        for field in ("id", "mount"):
            with self.subTest(field=field):
                self.state = self.root / field
                result = self.run_driver(scenario="missing")
                self.assertNotEqual(result.returncode, 0)
                path = self.root / "node.json"
                node = json.loads(path.read_text())
                if field == "id":
                    node[0]["Id"] = "e" * 64
                else:
                    node[0]["Mounts"][0]["Source"] = str(self.root / "foreign")
                path.write_text(json.dumps(node))
                before = len(self.calls())
                result = self.run_driver("cleanup")
                self.assertNotEqual(result.returncode, 0)
                calls = self.calls()[before:]
                self.assertFalse(any(call[:2] in (["docker", "exec"], ["docker", "run"], ["kind", "delete"]) for call in calls))
                self.assertTrue(path.exists())

    def test_cleanup_cannot_race_run_before_ledger(self):
        args = ["bash", str(RUNNER), "run", str(self.input), str(self.state)]
        proc = subprocess.Popen(args, env=dict(self.env, PODCLOUD_SCENARIO="blocked"),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 10
            while not (self.root / "exec-paused").exists():
                self.assertIsNone(proc.poll(), "run exited before the simulated pre-ledger pause")
                self.assertLess(time.monotonic(), deadline, "run did not reach pre-ledger pause")
                time.sleep(0.01)
            self.assertFalse((self.state / "ledger.json").exists())
            before = len(self.calls())
            result = self.run_driver("cleanup")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("exclusive Cloud runner lock", result.stderr)
            self.assertEqual(self.calls()[before:], [])
            self.assertTrue((self.root / "node.json").exists())
        finally:
            (self.root / "release-exec").touch()
            stdout, stderr = proc.communicate(timeout=15)
        self.assertEqual(proc.returncode, 0, stdout + stderr)

    def test_orphaned_preledger_process_requires_local_stop_proof(self):
        result = self.run_driver(scenario="orphan")
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((self.state / "execution-started").exists())
        self.assertFalse((self.state / "ledger.json").exists())
        result = self.run_driver("cleanup", "orphan-busy")
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((self.root / "node.json").exists())
        before = len(self.calls())
        result = self.run_driver("cleanup", "orphan-closed")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.root / "node.json").exists())
        executed = [call for call in self.calls()[before:] if call[:2] == ["docker", "exec"]]
        self.assertEqual(len(executed), 1)
        self.assertIn("^TestPodProviderCloudLocalCleanup$", executed[0])


if __name__ == "__main__":
    unittest.main()
