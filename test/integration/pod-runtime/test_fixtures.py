#!/usr/bin/env python3
"""Offline regressions for the runtime runner's source/provenance gate."""
import copy
import json
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

import fixtures


class RuntimeInputsTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.source = Path(self.directory.name)
        root = Path(__file__).resolve().parents[3]
        for name in ("images/node-guest/c8s/mkosi.sync",
                     "images/node-guest/c8s/image-policy.yaml.in",
                     "test/integration/cluster/lib.sh",
                     "internal/cmds/nri-image-policy/pod_runtime_kubelet_integration_linux_test.go",
                     "internal/cmds/nri-image-policy/pod_runtime_recovery_integration_linux_test.go",
                     "internal/testdata/node-identities.json"):
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((root / name).read_bytes())
        self.pins = json.loads(Path(__file__).with_name("runtime-pins.json").read_text())

    def test_current_source_and_both_architectures(self):
        for architecture in ("amd64", "arm64"):
            with self.subTest(architecture=architecture):
                runner = fixtures.validate_runtime_inputs(self.source, self.pins, architecture)
                self.assertRegex(runner, r"^kindest/node:.*@sha256:[a-f0-9]{64}$")

    def test_prepare_labels_provenance_without_byte_equivalence(self):
        stage = self.source / "stage"
        stage.mkdir()
        with patch.object(fixtures.subprocess, "check_output", side_effect=[b"0" * 40, b""]):
            fixtures.prepare(self.source, stage, "amd64")
        receipt = json.loads((stage / "inputs.json").read_text())
        self.assertEqual(receipt["runtimePlatformDigest"], self.pins["platforms"]["amd64"])
        self.assertEqual(receipt["guestAirgapBundlesAMD64"], self.pins["guestAirgapBundlesAMD64"])
        self.assertEqual(receipt["historicalRuntimeAirgapDigest"], self.pins["historicalRuntimeAirgapDigest"])
        self.assertNotIn("airgapFloorDigest", receipt)
        self.assertIn("runtime/CNI guest airgap byte equivalence unverified", receipt["runtimeProvenance"])

    def test_guest_version_and_bundle_drift(self):
        path = self.source / "images/node-guest/c8s/mkosi.sync"
        original = path.read_text()
        cases = [(self.pins["rke2Version"], "v0.0.0+rke2r1", "RKE2 version")]
        cases.extend((digest, "0" * 64, bundle + " bundle")
                     for bundle, digest in self.pins["guestAirgapBundlesAMD64"].items())
        for before, after, reason in cases:
            with self.subTest(reason=reason):
                self.assertEqual(original.count(before), 1)
                path.write_text(original.replace(before, after))
                with self.assertRaisesRegex(ValueError, reason):
                    fixtures.validate_runtime_inputs(self.source, self.pins, "amd64")
        path.write_text(original)
        assignment = 'RKE2_IMAGES_CORE_SHA256="' + self.pins["guestAirgapBundlesAMD64"]["core"] + '"'
        for changed in (original.replace(assignment, ""), original + "\n" + assignment + "\n"):
            path.write_text(changed)
            with self.assertRaisesRegex(ValueError, "core bundle"):
                fixtures.validate_runtime_inputs(self.source, self.pins, "amd64")

    def test_cni_rule_drift(self):
        path = self.source / "images/node-guest/c8s/image-policy.yaml.in"
        original = path.read_text()
        digest = self.pins["cni"]["airgapFloorDigest"]
        image = "docker.io/rancher/hardened-cni-plugins:" + self.pins["cni"]["version"]
        cases = {
            "digest": original.replace(digest, "sha256:" + "0" * 64),
            "version": original.replace(image, image + "-changed"),
            "not-init": original.replace("      cilium:\n        initContainers:", "      cilium:\n        containers:"),
            "duplicate": original + '\n            image: "' + image + '"\n',
        }
        for reason, changed in cases.items():
            with self.subTest(reason=reason):
                self.assertNotEqual(original, changed)
                path.write_text(changed)
                with self.assertRaisesRegex(ValueError, "Cilium init rule"):
                    fixtures.validate_runtime_inputs(self.source, self.pins, "amd64")

    def test_malformed_registry_pins(self):
        for family in ("runtime", "cni"):
            for field in ("registryIndex", "amd64", "arm64"):
                with self.subTest(family=family, field=field):
                    pins = copy.deepcopy(self.pins)
                    target = pins if family == "runtime" else pins["cni"]
                    if field == "registryIndex":
                        target[field] = "sha256:bad"
                    else:
                        target["platforms"][field] = "sha256:bad"
                    with self.assertRaisesRegex(ValueError, "sha256 pins"):
                        fixtures.validate_runtime_inputs(self.source, pins, "amd64")


if __name__ == "__main__":
    unittest.main()
