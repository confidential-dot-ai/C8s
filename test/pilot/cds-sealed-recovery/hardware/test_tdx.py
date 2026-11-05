import copy
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

import tdx


class TDXPlacementTests(unittest.TestCase):
    def test_generic_tdx_label_never_substitutes_for_cloud_host_tee(self):
        with tempfile.TemporaryDirectory() as directory:
            node = {"metadata": {"name": "worker", "uid": "node-uid", "labels": {"kubevirt.io/tdx": "true"}},
                    "status": {"nodeInfo": {"bootID": "boot"}, "conditions": [
                        {"type": k, "status": v} for k, v in {"Ready": "True", "CloudQualified": "True",
                        "MemoryPressure": "False", "DiskPressure": "False", "PIDPressure": "False"}.items()]}}
            class Kube:
                status = {"tee": "tdx", "nodeUID": "node-uid", "schedulable": True}
                def call(self, method, path, **kwargs):
                    assert method == "GET"
                    if path == "/api/v1/nodes": return 200, {"items": [node]}
                    if path.endswith("/hosts/worker"): return 200, {"status": self.status}
                    if path.endswith("/virtualmachineinstances"): return 200, {"items": []}
                    raise AssertionError(path)
            kube = Kube()
            args = SimpleNamespace(directory=directory, platform="tdx", nodes=["worker"])
            run = tdx.TDXRun(args, kube, lambda p, v: None)
            run.health(capture=True)
            valid = kube.status
            for update in ({"tee": "sev-snp"}, {"nodeUID": "replacement"}, {"schedulable": False}, {"shuttingDown": True}):
                kube.status = valid | update
                with self.assertRaisesRegex(RuntimeError, "Cloud Host"): run.health(capture=True)
            kube.status = valid
            node["metadata"]["labels"]["node-role.kubernetes.io/control-plane"] = ""
            with self.assertRaisesRegex(RuntimeError, "control-plane"): run.health(capture=True)

    def test_tdx_cleanup_scope_is_still_exact(self):
        run = "cds-tdx-0123456789ab"
        item = {"kind": "Pod", "metadata": {"name": run+"-populate", "namespace": "p-internal", "labels": {tdx.LABEL: run}}}
        self.assertEqual("/api/v1/namespaces/p-internal/pods/"+run+"-populate", tdx.resource_path(item))
        for field, value in (("name", "customer-vm"), ("namespace", "kube-system")):
            bad = copy.deepcopy(item)
            bad["metadata"][field] = value
            with self.assertRaises(RuntimeError): tdx.resource_path(bad)


if __name__ == "__main__": unittest.main()
