import unittest
from types import SimpleNamespace
from unittest.mock import patch

from tdx_integrated import TDXIntegrated


class MixedPlatformBoundaryTests(unittest.TestCase):
    def test_four_distinct_workers_required_before_artifact_or_cloud_work(self):
        for nodes in (["a","b"], ["a","b","c","c"], ["a","b","c","d","e"]):
            actor = object.__new__(TDXIntegrated)
            actor.args = SimpleNamespace(nodes=nodes)
            with patch("tdx_integrated.image_inputs") as images:
                with self.assertRaisesRegex(RuntimeError,"two independent"):
                    actor.exercise()
                images.assert_not_called()

    def test_worker_family_cannot_silently_fall_back_to_snp(self):
        actor = object.__new__(TDXIntegrated)
        actor.args = SimpleNamespace(nodes=["a","b","c","d"],platforms={n:"snp" for n in "abcd"})
        with patch("tdx_integrated.image_inputs") as images:
            with self.assertRaisesRegex(RuntimeError,"worker families"):
                actor.exercise()
            images.assert_not_called()

    def test_recovery_excludes_both_original_custody_and_cds_workers(self):
        actor = object.__new__(TDXIntegrated)
        actor.state = {"excluded_recovery_nodes":["original-snp","original-tdx"]}
        for node in actor.state["excluded_recovery_nodes"]:
            vm = {"spec":{"template":{"spec":{"nodeSelector":{"kubernetes.io/hostname":node}}}}}
            with patch.object(actor,"create") as create:
                with self.assertRaisesRegex(RuntimeError,"original host excluded"):
                    actor.boot_pair((("receiver",vm),),"recover")
                create.assert_not_called()


if __name__ == "__main__": unittest.main()
