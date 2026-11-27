import hashlib
import json
import runpy
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

PREPARE = runpy.run_path(str(Path(__file__).with_name("prepare")))


class MediaTests(unittest.TestCase):
    def test_rendered_images(self):
        fixture = {"spec": {"template": {"spec": {
            "initContainers": [{"image": "nginxinc/test:v1@sha256:" + "a" * 64}],
            "containers": [{"image": "pause@sha256:" + "b" * 64}],
        }}}}
        self.assertEqual(PREPARE["workload_images"](fixture), {
            "docker.io/nginxinc/test@sha256:" + "a" * 64, "docker.io/library/pause@sha256:" + "b" * 64})
        with self.assertRaisesRegex(ValueError, "lacks a digest"):
            PREPARE["workload_images"]({"containers": [{"image": "registry.k8s.io/pause:latest"}]})

    def test_site_inputs(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            site = root / "site"
            site.mkdir()
            (site / "foo").write_text("input")
            checksum = hashlib.sha256(b"input").hexdigest()
            (site / "link").symlink_to("foo")
            for name, expected in [("foo", "missing site files"), ("link", "expected a regular"),
                                   ("../site/foo", "invalid site inventory")]:
                with self.subTest(name=name):
                    inventory = f"{checksum}  {name}\n".encode()
                    (site / "SHA256SUMS").write_bytes(inventory)
                    with self.assertRaisesRegex(ValueError, expected):
                        PREPARE["site_inputs"](site, root / "dst", hashlib.sha256(inventory).hexdigest())
            with self.assertRaisesRegex(ValueError, "approved SHA-256"):
                PREPARE["site_inputs"](site, root / "dst", "0" * 64)

    def test_collateral_object(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "snapshots").mkdir()
            (root / "objects").mkdir()
            blob = b"signed object fixture"
            pin = hashlib.sha256(blob).hexdigest()
            (root / "objects" / pin).write_bytes(blob)
            base = "https://api.trustedservices.intel.com"
            names = [f"{base}/tdx/certification/v4/tcb?fmspc=b0c06f000000", f"{base}/tdx/certification/v4/qe/identity",
                     f"{base}/sgx/certification/v4/pckcrl?ca=platform&encoding=der",
                     "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der",
                     "nvidia/policy", "nvidia/rim/test", "nvidia/ocsp/" + "e" * 64]
            target = {"id": "fixture", "intelFMSPC": "b0c06f000000", "pckCA": "platform"}
            raw = json.dumps({"generation": 2, "target": "fixture", "expiresAt": "2099-01-01T00:00:00+00:00",
                              "objects": {name: {"sha256": pin} for name in names}}).encode()
            selected = hashlib.sha256(raw).hexdigest()
            manifest = root / "snapshots" / (selected + ".json")
            manifest.write_bytes(raw)
            (root / "active").write_text(json.dumps({"generation": 2, "sha256": selected}))
            subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519", "-out", "key"], cwd=root, check=True)
            public = subprocess.check_output(["openssl", "pkey", "-in", "key", "-pubout"], cwd=root, text=True)
            (root / "profile.json").write_text(json.dumps({"mediaPublicKey": public, "target": "fixture"}))
            subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", "key", "-rawin", "-in", manifest,
                            "-out", manifest.with_suffix(".sig")], cwd=root, check=True)
            PREPARE["collateral"](root, target)
            with self.assertRaisesRegex(ValueError, "different site"):
                PREPARE["collateral"](root, target | {"id": "another"})
            with self.assertRaisesRegex(ValueError, "missing snapshot objects"):
                PREPARE["collateral"](root, target | {"pckCA": "processor"})
            (root / "objects" / pin).write_bytes(b"substitution")
            with self.assertRaisesRegex(ValueError, "collateral object digest mismatch"):
                PREPARE["collateral"](root, target)


if __name__ == "__main__":
    unittest.main()
