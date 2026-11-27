import hashlib
import io
import json
import runpy
import subprocess
import tarfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

SCRIPT = Path(__file__).with_name("qualify").resolve()
QUALIFY = runpy.run_path(str(SCRIPT))


class QualificationTest(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        blobs = {hashlib.sha256(json.dumps(i).encode()).hexdigest(): i for i in ("rim", "ocsp", "policy")}
        rim_pin, ocsp_pin, policy_pin = blobs
        rim = {"nvidia/rim/fixture": rim_pin}
        ocsp = {"nvidia/ocsp/" + "c" * 64: ocsp_pin}
        devices = [{"ueid": f"gpu-{n}", "rims": rim, "ocsp": ocsp} for n in range(8)]
        self.target = {"id": "test-site", "gpuUEIDs": [d["ueid"] for d in devices],
                       "mediaTurnaroundSeconds": 30, "maximumStatusAgeSeconds": 3600}
        self.manifest = {"target": "test-site", "generation": 2, "expiresAt": "2099-01-01T00:00:00+00:00",
                         "objects": {k: {"sha256": v} for k, v in (rim | ocsp | {"nvidia/policy": policy_pin}).items()}}
        pin = hashlib.sha256(json.dumps(self.manifest).encode()).hexdigest()
        self.review = {"devices": devices, "policySha256": policy_pin, "target": "test-site", "generation": 2,
                       "snapshotSha256": pin, "observedRefreshSeconds": 60, "maximumStatusAgeSeconds": 3600,
                       "offlineB200Verified": True, "limitingObject": next(iter(ocsp)),
                       "earliestExpiryUtc": "2099-01-01T00:00:00Z"}
        with tarfile.open(self.root / "software.tar", "w") as archive:
            for name, obj in [("site/target.json", self.target), ("site/collateral/active", {"generation": 2, "sha256": pin}),
                              (f"site/collateral/snapshots/{pin}.json", self.manifest),
                              ("release/release-statement.json", {"tag": "v1.2.3"}),
                              *[(f"site/collateral/objects/{p}", data) for p, data in blobs.items()]]:
                raw = json.dumps(obj).encode()
                member = tarfile.TarInfo("./" + name)
                member.size = len(raw)
                archive.addfile(member, io.BytesIO(raw))
        (self.root / "inventory.sha256").write_bytes(b"fixture")
        self.review["archiveSha256"] = QUALIFY["sha256"](self.root / "software.tar")
        self.review["inventorySha256"] = QUALIFY["sha256"](self.root / "inventory.sha256")

    def test_rejects_gaps(self):
        verify = QUALIFY["verify_bytes"]
        failures = [({"devices": self.review["devices"][1:]}, "GPU inventory"),
                    ({"policySha256": "0" * 64}, "policy digest"),
                    ({"earliestExpiryUtc": (datetime.now(UTC) + timedelta(seconds=20)).isoformat()}, "refresh interval"),
                    ({"generation": 1}, "target and generation"),
                    ({"archiveSha256": "1" * 64}, "software.tar differs")]
        for change, expected in failures:
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, expected):
                verify(self.root, json.dumps(self.review | change).encode(), "v1.2.3")
        self.review["devices"][0]["ocsp"] = {"nvidia/ocsp/" + "c" * 64: "a" * 64}
        with self.assertRaisesRegex(ValueError, "unqualified ocsp"):
            verify(self.root, json.dumps(self.review).encode(), "v1.2.3")

    def test_sign_and_receive(self):
        for key, principal in [("qualifier", "c8s-qualification"), ("media", "c8s-release")]:
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key], cwd=self.root, check=True)
            (self.root / (key + ".allowed")).write_text(f"{principal} " + (self.root / (key + ".pub")).read_text())
        (self.root / "review.json").write_text(json.dumps(self.review))
        subprocess.run(["ssh-keygen", "-Y", "sign", "-f", "qualifier", "-n", "c8s-b200-qualification", "review.json"],
                       cwd=self.root, check=True, capture_output=True)
        subprocess.run([SCRIPT, "seal", "v1.2.3", ".", "qualifier.allowed", "review.json", "media"],
                       cwd=self.root, check=True, capture_output=True)
        verify = [SCRIPT, "verify", "v1.2.3", ".", "media.allowed"]
        subprocess.run(verify, cwd=self.root, check=True, capture_output=True)
        (self.root / "inventory.sha256").write_bytes(b"new inventory")
        self.assertNotEqual(subprocess.run(verify, cwd=self.root, capture_output=True, check=False).returncode, 0)


if __name__ == "__main__":
    unittest.main()
