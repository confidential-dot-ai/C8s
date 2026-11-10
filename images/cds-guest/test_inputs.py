#!/usr/bin/env python3
"""Exercise source selection and trust-root rejection without building an image."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


IMAGE = Path(__file__).resolve().parent
PINS = json.loads((IMAGE.parent.parent / ".github/build-pins.json").read_text())
SOURCE = "1" * 40


class ImageInputs(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cds-image-inputs-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.builder = self.directory / "builder with spaces"
        self.recipe = self.directory / "recipe/images/cds-guest"
        self.recipe.mkdir(parents=True)
        shutil.copy2(IMAGE / "build", self.recipe / "build")
        self.pins = self.recipe.parent.parent / ".github/build-pins.json"
        self.pins.parent.mkdir()
        self.tools = self.directory / "tools"
        self.tools.mkdir()
        (self.builder / "bin").mkdir(parents=True)
        self.binary = self.directory / "c8s"
        shutil.copyfile("/bin/true", self.binary)
        self.binary.chmod(0o755)
        self.digest = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        self.args = self.directory / "arguments.json"
        self.metadata = self.directory / "metadata.txt"
        self.metadata.write_text(
            "c8s: go1.27.3\n\tpath\tgithub.com/confidential-dot-ai/c8s/cmd/c8s\n"
            "\tbuild\tCGO_ENABLED=0\n\tbuild\tGOOS=linux\n\tbuild\tGOARCH=amd64\n"
            f"\tbuild\tvcs=git\n\tbuild\tvcs.revision={SOURCE}\n\tbuild\tvcs.modified=false\n"
        )
        self.script(self.tools / "inspect-go", '#!/bin/sh\ncat "$TEST_METADATA"\n')
        self.script(self.builder / "bin/confos", """#!/usr/bin/env python3
import hashlib,json,os,pathlib,sys
pathlib.Path(os.environ['TEST_ARGUMENTS']).write_text(json.dumps(sys.argv[1:]))
output=pathlib.Path('output',sys.argv[2]); output.mkdir(parents=True)
if '--extra' in sys.argv:
 stage=pathlib.Path(sys.argv[sys.argv.index('--extra')+1])/'usr/local/bin'
 (output/'staged-binaries.json').write_text(json.dumps({p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in stage.iterdir()}))
kernel=pathlib.Path('output/kernel')
if kernel.exists():
 (output/'reused-kernel.json').write_text(json.dumps({p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in kernel.iterdir()}))
""")
        (self.builder / ".gitignore").write_text("mkosi/base/mkosi.local/\nmkosi/mkosi.pkgcache/\ntarget/\noutput/\n")
        self.git_env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        self.git_env.update(GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_SYSTEM="/dev/null")
        self.git("init", "--quiet")
        self.git("add", ".")
        self.git("-c", "user.name=Image input test", "-c", "user.email=test@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "Fixture builder")
        self.builder_commit = self.git("rev-parse", "HEAD").stdout.strip()
        fixture_pins = json.loads(json.dumps(PINS))
        fixture_pins["builds"]["node-image"]["confos_ref"] = self.builder_commit
        self.pins.write_text(json.dumps(fixture_pins))
        self.env = {k: v for k, v in self.git_env.items() if not k.startswith("C8S_")}
        self.env.update(
            PATH=str(self.tools) + os.pathsep + os.environ["PATH"],
            CONFOS_DIR=str(self.builder), C8S_BINARY=str(self.binary),
            C8S_BINARY_SHA256=self.digest, C8S_SOURCE_COMMIT=SOURCE,
            C8S_GO=str(self.tools / "inspect-go"), TEST_METADATA=str(self.metadata),
            TEST_ARGUMENTS=str(self.args),
        )

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.builder), "-c", "core.hooksPath=/dev/null", *args],
                              env=self.git_env, check=True, capture_output=True, text=True)

    @staticmethod
    def script(path, contents):
        path.write_text(contents)
        path.chmod(0o755)

    def build(self, success=True, **overrides):
        env = self.env | overrides
        self.args.unlink(missing_ok=True)
        result = subprocess.run([str(self.recipe / "build")], env=env, capture_output=True, text=True)
        if success:
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads(self.args.read_text())
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.args.exists(), "invalid inputs reached the builder")

    def test_local_binary_provenance_and_fixed_custody_composition(self):
        arguments = self.build(C8S_GUEST_ROLE="custody")
        self.assertEqual(arguments[:2], ["build", "cds-custody"])
        self.assertEqual(arguments[arguments.index("--platform") + 1], "snp")
        self.assertEqual(arguments[arguments.index("--smp") + 1], "2")
        self.assertEqual(
            [arguments[i + 1] for i, value in enumerate(arguments) if value == "--profile"],
            ["attest", "cds"],
        )
        self.assertEqual(
            [Path(arguments[i + 1]).name for i, value in enumerate(arguments) if value == "--profile-dir"],
            ["cds", "custody"],
        )
        self.assertFalse(Path(arguments[arguments.index("--extra") + 1]).exists(), "staging survived build")
        self.assertEqual(
            json.loads((self.builder / "output/cds-custody/c8s-source.json").read_text()),
            {"source_commit": SOURCE, "c8s_sha256": self.digest, "confos_commit": self.builder_commit},
        )
        self.build(False)  # Generated output is not a fresh source checkout.

    def test_published_cds_keeps_existing_composition(self):
        arguments = self.build(C8S_BINARY="", C8S_BINARY_SHA256="", C8S_SOURCE_COMMIT="", C8S_REF="published")
        self.assertEqual(arguments[:2], ["build", "cds"])
        self.assertEqual(arguments[arguments.index("--platform") + 1], "both")
        self.assertIn("c8s-ref=published", arguments)
        self.assertNotIn("--extra", arguments)
        self.assertNotIn("--smp", arguments)

    def workload_inputs(self):
        return dict(C8S_GUEST_ROLE="native-workload", C8S_BINARY="", C8S_BINARY_SHA256="",
                    C8S_NATIVE_WORKLOAD_BINARY=str(self.binary), C8S_NATIVE_WORKLOAD_SHA256=self.digest)

    def workload_metadata(self):
        self.metadata.write_text(self.metadata.read_text().replace(
            "github.com/confidential-dot-ai/c8s/cmd/c8s",
            "github.com/confidential-dot-ai/c8s/internal/cmds/cds.test"))

    def test_native_workload_uses_only_explicit_test_binary(self):
        self.workload_metadata()
        arguments = self.build(**self.workload_inputs())
        self.assertEqual(arguments[:2], ["build", "cds-native-workload"])
        self.assertEqual(arguments[arguments.index("--platform") + 1], "both")
        self.assertEqual(arguments[arguments.index("--smp") + 1], "2")
        self.assertEqual([Path(arguments[i + 1]).name for i, v in enumerate(arguments) if v == "--profile-dir"],
                         ["cds", "native-workload"])
        self.assertIn("native-workload-sha256=" + self.digest, arguments)
        output = self.builder / "output/cds-native-workload"
        self.assertEqual(json.loads((output / "staged-binaries.json").read_text()),
                         {"cds-native-workload.test": self.digest})
        self.assertEqual(json.loads((output / "c8s-source.json").read_text()),
                         {"source_commit": SOURCE, "native_workload_sha256": self.digest,
                          "confos_commit": self.builder_commit})

    def test_native_workload_has_no_release_or_production_binary_fallback(self):
        inputs = self.workload_inputs()
        self.build(False, **inputs)  # Production main-package metadata cannot select a test image.
        self.workload_metadata()
        for override in (
            {"C8S_REF": "published"}, {"C8S_BINARY": str(self.binary)},
            {"C8S_NATIVE_WORKLOAD_BINARY": ""}, {"C8S_NATIVE_WORKLOAD_SHA256": ""},
            {"C8S_NATIVE_WORKLOAD_SHA256": "0" * 64}, {"C8S_SOURCE_COMMIT": "2" * 40},
            {"C8S_GUEST_ROLE": "cds"}, {"C8S_GUEST_ROLE": "custody"},
        ):
            with self.subTest(override=override):
                self.build(False, **(inputs | override))

    def test_ambiguous_or_wrong_provenance_never_reaches_builder(self):
        for override in (
            {"C8S_REF": "published"}, {"C8S_BINARY_SHA256": "0" * 64},
            {"C8S_SOURCE_COMMIT": "2" * 40}, {"C8S_GUEST_ROLE": "dev"},
            {"C8S_SOURCE_COMMIT": ""}, {"C8S_BINARY_SHA256": ""},
        ):
            with self.subTest(override=override):
                self.build(False, **override)
        pins = self.pins.read_text()
        self.pins.write_text(pins.replace(self.builder_commit, "2" * 40))
        self.build(False)
        self.pins.write_text(pins)
        original = self.metadata.read_text()
        for bad in ("vcs.modified=true", "GOARCH=arm64", "CGO_ENABLED=1"):
            key = bad.split("=", 1)[0]
            lines = ["\tbuild\t" + bad if "\t" + key + "=" in line else line for line in original.splitlines()]
            self.metadata.write_text("\n".join(lines) + "\n")
            with self.subTest(metadata=bad):
                self.build(False)

    def test_modified_and_staged_builder_sources_rejected(self):
        with (self.builder / "bin/confos").open("a") as builder:
            builder.write("# changed recipe\n")
        self.build(False)
        self.git("add", "bin/confos")
        self.build(False)

    def test_untracked_and_ignored_consumed_inputs_rejected(self):
        for name in (
            "mkosi/base/mkosi.local.conf", "mkosi/base/mkosi.conf.d/extra.conf",
            "mkosi/base/mkosi.local/mkosi.extra/etc/systemd/system/injected.service",
            ".cargo/config.toml", "target/release/confos",
            "mkosi/mkosi.pkgcache/cache/apt/archives/injected.deb",
        ):
            with self.subTest(path=name):
                target = self.builder / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("unreviewed input\n")
                self.build(False)
                target.unlink()
                parent = target.parent
                while parent != self.builder:
                    parent.rmdir()
                    parent = parent.parent
                self.assertEqual(self.git("ls-files", "--others", "--directory").stdout, "")

    def kernel_reuse(self):
        reuse = self.directory / "verified kernel"
        reuse.mkdir()
        (reuse / "vmlinuz").write_bytes(b"verified prior kernel")
        kernel_hash = hashlib.sha256((reuse / "vmlinuz").read_bytes()).hexdigest()
        (reuse / "manifest.json").write_text(json.dumps({"version": 1, "outputs": {"vmlinuz_sha256": kernel_hash}}))
        return reuse, {"C8S_KERNEL_REUSE_DIR": str(reuse),
                       "C8S_KERNEL_MANIFEST_SHA256": hashlib.sha256((reuse / "manifest.json").read_bytes()).hexdigest()}

    def test_explicit_kernel_reuse_after_fresh_checkout_check(self):
        reuse, inputs = self.kernel_reuse()
        rogue = self.builder / "mkosi.local.conf"
        rogue.write_text("unreviewed config")
        self.build(False, **inputs)
        self.assertFalse((self.builder / "output/kernel").exists())
        rogue.unlink()
        self.build(**inputs)
        self.assertEqual(json.loads((self.builder / "output/cds/reused-kernel.json").read_text()),
                         {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in reuse.iterdir()})

    def test_kernel_reuse_rejects_unpinned_changed_and_additional_inputs(self):
        reuse, inputs = self.kernel_reuse()
        for override in ({"C8S_KERNEL_MANIFEST_SHA256": ""}, {"C8S_KERNEL_MANIFEST_SHA256": "0" * 64},
                         {"C8S_KERNEL_REUSE_DIR": ""},
                         {"C8S_BINARY": "", "C8S_BINARY_SHA256": "", "C8S_SOURCE_COMMIT": "", "C8S_REF": "published"}):
            with self.subTest(override=override):
                self.build(False, **(inputs | override))
        original = (reuse / "vmlinuz").read_bytes()
        (reuse / "vmlinuz").write_bytes(b"corrupt kernel")
        self.build(False, **inputs)
        (reuse / "vmlinuz").unlink()
        (reuse / "vmlinuz").symlink_to(self.binary)
        self.build(False, **inputs)
        (reuse / "vmlinuz").unlink()
        (reuse / "vmlinuz").write_bytes(original)
        (reuse / ".unexpected").write_text("ignored payload")
        self.build(False, **inputs)
        self.assertFalse((self.builder / "output/kernel").exists())

    def test_sync_rechecks_local_bytes_and_fetches_only_pinned_attester(self):
        self.check_sync_binary("c8s", "c8s-binary-sha256")

    def test_sync_rechecks_native_workload_bytes_without_production_binary(self):
        self.check_sync_binary("cds-native-workload.test", "native-workload-sha256")

    def check_sync_binary(self, binary_name, sync_input):
        sync = self.directory / "sync"
        inputs = sync / "mkosi.local/.confos-sync-inputs"
        stage = sync / "mkosi.local/mkosi.extra/usr/local/bin"
        inputs.mkdir(parents=True)
        stage.mkdir(parents=True)
        shutil.copyfile(self.binary, stage / binary_name)
        (stage / binary_name).chmod(0o755)
        (inputs / sync_input).write_text(self.digest)
        (inputs / "attestation-api-digest").write_text(PINS["builds"]["node-image"]["attestation_api_digest"])
        requests = self.directory / "registry.txt"
        self.script(self.tools / "oras", """#!/usr/bin/env python3
import io,json,os,pathlib,sys,tarfile
with open(os.environ['TEST_REGISTRY'],'a') as log: log.write(' '.join(sys.argv[1:])+'\\n')
assert sys.argv[-1].startswith('ghcr.io/confidential-dot-ai/attestation-api@sha256:')
if sys.argv[1:3]==['manifest','fetch']:
 print(json.dumps({'manifests':[{'platform':{'architecture':'amd64'},'digest':'sha256:'+'a'*64}],
                   'layers':[{'mediaType':'application/vnd.oci.image.layer.v1.tar+gzip','digest':'sha256:'+'b'*64}]}))
else:
 destination=sys.argv[sys.argv.index('--output')+1]
 with tarfile.open(destination,'w:gz') as archive:
  info=tarfile.TarInfo('attestation-api'); data=b'pinned-attester'; info.size=len(data)
  archive.addfile(info,io.BytesIO(data))
""")
        env = self.env | {"SRCDIR": str(sync), "TEST_REGISTRY": str(requests)}
        def run():
            return subprocess.run(["bash", str(IMAGE / "cds/mkosi.sync")], env=env, capture_output=True, text=True)
        result = run()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(hashlib.sha256((stage / binary_name).read_bytes()).hexdigest(), self.digest)
        self.assertEqual((stage / "attestation-api").read_bytes(), b"pinned-attester")
        self.assertEqual({p.name for p in stage.iterdir()}, {binary_name, "attestation-api"})
        before = requests.read_text()
        (inputs / "c8s-ref").write_text("published")
        self.assertNotEqual(run().returncode, 0)
        self.assertEqual(requests.read_text(), before, "ambiguous local binary reached registry fetching")
        (inputs / "c8s-ref").unlink()
        (stage / binary_name).write_bytes(b"changed after snapshot")
        self.assertNotEqual(run().returncode, 0)
        self.assertEqual(requests.read_text(), before, "bad local binary reached registry fetching")

    def root(self, certificate_name="Public_Root", directory="root"):
        root = self.directory / directory
        files = {
            "etc/attestation-api/config.toml": 'bind = "0.0.0.0:8400"\n',
            "etc/shadow": "root:!:19800:0:99999:7:::\n",
            "etc/cloud/cloud-init.disabled": "",
            "etc/systemd/network/80-dhcp.network": "[Network]\nDHCP=yes\n",
            "etc/systemd/system/cds.service": "[Service]\nExecStart=/usr/local/bin/c8s cds\n",
            "etc/ca-certificates.conf": f"# package roots\nmozilla/{certificate_name}.crt\n",
            f"usr/share/ca-certificates/mozilla/{certificate_name}.crt": "public-package-root\n",
            "etc/ssl/certs/ca-certificates.crt": "public-package-root\n",
        }
        for name, content in files.items():
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
        (root / "usr/local/share/ca-certificates").mkdir(parents=True)
        (root / f"etc/ssl/certs/{certificate_name}.pem").symlink_to(f"/usr/share/ca-certificates/mozilla/{certificate_name}.crt")
        (root / "etc/ssl/certs/00000000.0").symlink_to(f"{certificate_name}.pem")
        return root

    def finalize(self, root, success):
        result = subprocess.run(["bash", str(IMAGE / "cds/mkosi.finalize")],
                                env=self.env | {"BUILDROOT": str(root)}, capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode == 0, success, result.stderr)

    def test_public_roots_and_masked_host_execution_paths(self):
        root = self.root()
        self.finalize(root, True)
        for unit in ("serial-getty@.service", "rescue.service", "emergency.service", "debug-shell.service", "qemu-guest-agent.service"):
            self.assertEqual(os.readlink(root / "etc/systemd/system" / unit), "/dev/null")
        for generator in ("systemd-debug-generator", "systemd-run-generator", "systemd-getty-generator"):
            self.assertEqual(os.readlink(root / "etc/systemd/system-generators" / generator), "/dev/null")
        self.assertEqual((root / "etc/systemd/network/80-dhcp.network").stat().st_mode & 0o777, 0o644)

    def test_distribution_certificate_name_with_unicode_and_equals(self):
        root = self.root("NetLock_Arany_=Class_Gold=_Főtanúsítvány")
        self.finalize(root, True)

    def test_certificate_selection_rejects_traversal_nested_paths_and_controls(self):
        for index, value in enumerate(("mozilla/../Public_Root.crt", "mozilla/extra/Public_Root.crt",
                                       "mozilla/Public\r_Root.crt")):
            with self.subTest(selection=value):
                root = self.root(directory=f"invalid-{index}")
                (root / "etc/ca-certificates.conf").write_text(value + "\n")
                self.finalize(root, False)

    def test_certificate_selection_rejects_symlink_source(self):
        root = self.root()
        source = root / "usr/share/ca-certificates/mozilla/Public_Root.crt"
        source.unlink()
        source.symlink_to(root / "etc/ssl/certs/ca-certificates.crt")
        self.finalize(root, False)

    def test_certificate_selection_rejects_fifo_without_reading(self):
        for link in (False, True):
            with self.subTest(symlink=link):
                root = self.root(directory=f"fifo-{link}")
                source = root / "usr/share/ca-certificates/mozilla/Public_Root.crt"
                source.unlink()
                if link:
                    fifo = root / "unselected-fifo"
                    os.mkfifo(fifo)
                    source.symlink_to(fifo)
                else:
                    os.mkfifo(source)
                self.finalize(root, False)

    def test_certificate_links_reject_control_targets(self):
        selected = "/usr/share/ca-certificates/mozilla/Public_Root.crt"
        for index, (name, target) in enumerate((
            ("Public_Root.pem", selected + "\n"),
            ("Public_Root.pem", selected + "\n/unselected-root"),
            ("00000000.0", "Public_Root.pem\n"),
            ("Public_Root.pem", selected + "\r"),
        )):
            with self.subTest(target=target):
                root = self.root(directory=f"link-{index}")
                link = root / "etc/ssl/certs" / name
                link.unlink()
                link.symlink_to(target)
                self.finalize(root, False)

    def test_native_workload_fixed_invocation_and_bounded_lifetime(self):
        profile = IMAGE / "native-workload"
        unit = (profile / "mkosi.extra/etc/systemd/system/cds-native-workload.service").read_text()
        for setting in (
            "ExecStart=/usr/local/bin/cds-native-workload.test -test.run=^TestObjectNativeWorkloadGuest$ -test.timeout=0",
            "Environment=C8S_OBJECT_NATIVE_WORKLOAD=1", "CapabilityBoundingSet=CAP_NET_BIND_SERVICE",
            "AmbientCapabilities=CAP_NET_BIND_SERVICE", "RuntimeMaxSec=75min", "Restart=no",
            "SuccessAction=poweroff", "FailureAction=poweroff", "Requires=attestation-api.service",
            "DevicePolicy=closed", "NoNewPrivileges=yes",
        ):
            self.assertIn(setting, unit.splitlines())
        self.assertNotIn("DeviceAllow=", unit)
        root = self.root()
        target = root / "usr/local/bin/cds-native-workload.test"
        target.parent.mkdir(parents=True)
        shutil.copy2(self.binary, target)
        (root / "etc/systemd/system/cds-native-workload.service").write_text(unit)
        self.finalize(root, True)
        result = subprocess.run(["bash", str(profile / "mkosi.finalize")],
                                env=self.env | {"BUILDROOT": str(root)}, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(os.readlink(root / "etc/systemd/system/cds.service"), "/dev/null")
        self.assertFalse((root / "usr/local/bin/c8s").exists())

    def test_proxy_root_rejected_in_bundle(self):
        root = self.root()
        with (root / "etc/ssl/certs/ca-certificates.crt").open("a") as bundle:
            bundle.write("workspace-proxy-root\n")
        self.finalize(root, False)

    def test_proxy_root_rejected_outside_unchanged_bundle(self):
        root = self.root()
        (root / "etc/ssl/certs/workspace.pem").write_text("workspace-proxy-root\n")
        self.finalize(root, False)

    def test_hidden_proxy_root_rejected_outside_unchanged_bundle(self):
        root = self.root()
        (root / "etc/ssl/certs/.workspace.pem").write_text("workspace-proxy-root\n")
        self.finalize(root, False)

    def test_extra_local_root_rejected(self):
        root = self.root()
        (root / "usr/local/share/ca-certificates/workspace.crt").write_text("workspace-proxy-root\n")
        self.finalize(root, False)

    def test_alternate_ca_directory_and_dangling_link_rejected(self):
        for link in (False, True):
            with self.subTest(symlink=link):
                root = self.root(directory=f"alternate-{link}")
                alternate = root / "etc/pki/tls/certs"
                alternate.parent.mkdir(parents=True)
                if link:
                    alternate.symlink_to("/nonexistent-ca-directory")
                else:
                    alternate.mkdir()
                self.finalize(root, False)


if __name__ == "__main__":
    unittest.main()
