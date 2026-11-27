import hashlib
import json
import os
import re
import runpy
import shutil
import subprocess
import tomllib
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

REPO = Path(__file__).resolve().parents[2]
BUILD = runpy.run_path(str(Path(__file__).with_name("guest-profile")))["build"]


class GuestProfileTest(unittest.TestCase):
    def test_site_only(self):
        with TemporaryDirectory() as temp:
            site = Path(temp)
            output = site / "site-offline"
            (site / "collateral").mkdir()
            (site / "collateral/profile.json").write_text('{"target":"fixture"}')
            (site / "registry-ca.pem").write_text("fixture")
            (site / "target.json").write_text(json.dumps({
                "gpuUEIDs": [f"enrolled-{n}" for n in range(8)],
                "registry": "registry.site:5000", "dnsIPv4": "10.0.0.53", "ntpIPv4": "10.0.0.123",
            }))
            verifiers = site / "candidate"
            verifiers.mkdir()
            for role, source in (("ta", "/bin/true"), ("worker", "/bin/false")):
                shutil.copy(source, verifiers / role)
            (verifiers / "c8s").write_text('#!/bin/sh\n[ "$*" = "collateral selected-tdx --help" ] || exit 1\n'
                                          'echo "c8s collateral selected-tdx PROFILE [flags]"\n')
            hashes = {file.name: hashlib.sha256(file.read_bytes()).hexdigest() for file in verifiers.iterdir()}
            approval = site / "approved.json"
            approval.write_text(json.dumps(hashes))
            config = ('[server]\nbind = "0.0.0.0:8400"\n[attestation]\nplatforms=["tdx"]\n'
                      'tdx_quote_method="configfs"\n[verify]\nwarm=[]\n[verify.selected_tdx]\n'
                      'helper="/usr/local/bin/c8s"\nprofile="/etc/c8s-site/profile.json"\n')
            invalid = (config.replace("warm=[]", 'warm=["https://example.org"]'),
                       config.replace("/usr/local/bin/c8s", "/usr/bin/other"),
                       config.replace("/etc/c8s-site/profile.json", "/tmp/host.json"),
                       config.split("[verify.selected_tdx]")[0],
                       config.replace("0.0.0.0:8400", r"0.0.0.0\u003a8400"),
                       config.replace('bind = "', 'bind= "') + '[token]\nissuer="""\nbind = "0.0.0.0:8400"\n"""\n',
                       config + '[token]\nissuer="""\nbind = "0X0Y0Z0:8400"\n"""\n',
                       config + "[certs]\nprefetch_nras_jwks=false\n",
                       config.replace("0.0.0.0:8400", "0.0.0.0:9999") + '[auth]\nbind="0.0.0.0:8400"\n')
            for rejected in invalid:
                with self.subTest(rejected=rejected):
                    (site / "attestation-api.toml").write_text(rejected)
                    with self.assertRaises(ValueError):
                        BUILD(site, output, verifiers, approval)
                    self.assertFalse(output.exists())
            (site / "attestation-api.toml").write_text(config)
            approval.write_text(json.dumps(hashes | {"ta": "0" * 64}))
            with self.assertRaisesRegex(ValueError, "ta verifier differs"):
                BUILD(site, output, verifiers, approval)
            self.assertFalse(output.exists())
            approval.write_text(json.dumps(hashes))
            BUILD(site, output, verifiers, approval)
            etc = output / "mkosi.extra/etc"
            self.assertEqual(json.loads((etc / "c8s-site/gpu-ueids.json").read_text()),
                             [f"enrolled-{n}" for n in range(8)])
            dns = (etc / "systemd/resolved.conf.d/90-site.conf").read_text()
            self.assertIn("DNS=\nDNS=10.0.0.53\n", dns)
            self.assertIn("FallbackDNS=\n", dns)
            self.assertIn("NTP=\nNTP=10.0.0.123\nFallbackNTP=\n", (etc / "systemd/timesyncd.conf.d/90-site.conf").read_text())
            registry = tomllib.loads((etc / "containerd/certs.d/_default/hosts.toml").read_text())
            self.assertEqual(registry["server"], "https://registry.site:5000")
            self.assertEqual(registry["capabilities"], ["pull", "resolve"])
            self.assertEqual((etc / "c8s-site/profile.json").read_bytes(), (site / "collateral/profile.json").read_bytes())
            self.check_build_entry_points(site, output)
            source_dir = site / "mkosi.profiles"
            source_dir.mkdir()
            output.rename(source_dir / "site-offline")
            profile = source_dir / "site-offline"
            for role, marker, finalizer in (
                ("ta", "etc/systemd/system/ta.service", "images/ta-guest/ta/mkosi.finalize"),
                ("worker", "usr/lib/c8s/worker-image", "images/node-guest/worker/mkosi.finalize"),
            ):
                with self.subTest(role=role):
                    root = site / role
                    shutil.copytree(profile / "mkosi.extra", root)
                    (root / marker).parent.mkdir(parents=True)
                    (root / marker).touch()
                    binary = root / "usr/local/bin/attestation-api"
                    binary.parent.mkdir(parents=True)
                    binary.write_bytes(b"connected stock service")
                    env = os.environ | {"BUILDROOT": str(root), "SRCDIR": str(site)}
                    def run_site():
                        enter_namespace = [] if os.geteuid() == 0 else ["unshare", "--user", "--map-root-user"]
                        return subprocess.run([*enter_namespace, profile / "mkosi.finalize"], env=env, capture_output=True)
                    self.assertIn(b"expected server.bind", run_site().stderr)
                    subprocess.run([REPO / finalizer], env=env, check=True)
                    candidate = profile / "verifiers" / role
                    candidate.write_bytes(b"substituted after preparation")
                    self.assertIn(b"differs from the site-approved SHA-256", run_site().stderr)
                    self.assertEqual(binary.read_bytes(), b"connected stock service")
                    shutil.copyfile(verifiers / role, candidate)
                    # The approved helper uses /bin/sh. A shell on the builder cannot satisfy its guest dependency.
                    self.assertIn(b"failed its in-guest", run_site().stderr)
                    binary.write_bytes(b"connected stock service")
                    shell = Path("/bin/sh")
                    libraries = subprocess.check_output(["ldd", shell], text=True)
                    for dependency in (shell, *map(Path, re.findall(r"(/\S+)\s+\(", libraries))):
                        target = root / dependency.relative_to("/")
                        target.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy(dependency, target)
                    result = run_site()
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(hashlib.sha256(binary.read_bytes()).hexdigest(), hashes[role])
                    unit = root / "etc/systemd/system/gpu-cc-enforce.service.d/90-enrollment.conf"
                    self.assertEqual(unit.exists(), role == "worker")
                    if role == "worker":
                        self.assertIn("Environment=GPU_CC_ENROLLMENT=/etc/c8s-site/gpu-ueids.json", unit.read_text())
                    self.assertEqual(subprocess.run([binary]).returncode, 0 if role == "ta" else 1)
                    self.assertEqual((binary.parent / "c8s").read_bytes(), (verifiers / "c8s").read_bytes())
                    self.assertIn(b"matches the pinned connected verifier", run_site().stderr)
                    binary.write_bytes(b"connected stock service")
                    bad_helper = profile / "verifiers/c8s"
                    bad_helper.write_bytes(b"#!/bin/sh\nexit 0\n")
                    inventory = profile / "approved-verifiers.json"
                    inventory.write_text(json.dumps(hashes | {"c8s": hashlib.sha256(bad_helper.read_bytes()).hexdigest()}))
                    self.assertIn(b"failed its in-guest collateral selected-tdx", run_site().stderr)
                    shutil.copyfile(verifiers / "c8s", bad_helper)
                    inventory.write_text(json.dumps(hashes))

    def check_build_entry_points(self, directory, profile):
        confos = directory / "confos"
        (confos / "bin").mkdir(parents=True)
        command = confos / "bin/confos"
        command.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > args\n')
        command.chmod(0o755)
        (confos / "kernel").mkdir()
        (confos / "kernel/version").write_text("LINUX_VERSION=fixture\n")
        kernel = confos / "output/kernel/build/linux-fixture"
        kernel.mkdir(parents=True)
        shutil.copy(REPO / "images/node-guest/kernel/c8s.config", kernel / ".config")
        (confos / "output/kernel/manifest.json").touch()
        fetch = confos / "bin/confos-fetch-gpu"
        fetch.write_text("#!/bin/sh\nmkdir -p mkosi/base/mkosi.local/mkosi.extra\n")
        fetch.chmod(0o755)
        env = os.environ | {"C8S_REF": "fixture", "C8S_PLATFORM": "tdx", "CONFOS_DIR": str(confos),
                            "C8S_SITE_PROFILE": str(profile)}
        for role in ("ta-guest", "node-guest"):
            subprocess.run([REPO / "images" / role / "build"], env=env, check=True, capture_output=True)
            args = (confos / "args").read_text().splitlines()
            self.assertEqual(args[0], "build")
            self.assertEqual(args[args.index("--platform") + 1], "tdx")
            sources = [args[i + 1] for i, arg in enumerate(args) if arg == "--profile-dir"]
            self.assertEqual(sources[-1], str(profile))

        env.pop("C8S_SITE_PROFILE")
        subprocess.run([REPO / "images/ta-guest/build"], env=env, check=True)
        args = (confos / "args").read_text().splitlines()
        self.assertEqual(args[args.index("--platform") + 1], "both")
        self.assertNotIn(str(profile), args)


if __name__ == "__main__":
    unittest.main()
