import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

from metadata_process import MetadataProcess


class PipeTests(unittest.TestCase):
    def child(self, directory, code, timeout=0.15):
        executable = Path(directory) / "child"
        executable.write_text("#!" + sys.executable + "\n" + code)
        executable.chmod(0o700)
        return MetadataProcess(executable, Path(directory) / "state", "owned", subprocess.DEVNULL, timeout)

    def test_failure_poisoning_and_cleanup_are_bounded(self):
        programs = [
            "import time; time.sleep(20)",  # never reads a large request
            "import sys,time; sys.stdin.readline(); time.sleep(20)",  # lost reply
            "import sys; sys.stdin.readline(); sys.exit(0)",
            'import sys; sys.stdin.readline(); print(\'{"id":2,"status":200}\',flush=True)',
            'import sys; sys.stdin.readline(); print("x"*4000000,flush=True)',
        ]
        for code in programs:
            with self.subTest(code=code), tempfile.TemporaryDirectory() as directory:
                pipe = self.child(directory, code)
                started = time.monotonic()
                with self.assertRaises((RuntimeError, TimeoutError)):
                    pipe.answer({"id": 1, "data": "x"*200000})
                self.assertLess(time.monotonic()-started, 4)
                self.assertIsNotNone(pipe.process.poll())
                with self.assertRaisesRegex(RuntimeError, "closed"):
                    pipe.answer({"id": 1})
                pipe.close()

    def test_multiple_messages_preserve_conflict_without_reexecution(self):
        code = 'import sys,json\nfor line in sys.stdin:\n q=json.loads(line); print(json.dumps({"id":q["id"],"status":412}),flush=True)\n'
        with tempfile.TemporaryDirectory() as directory:
            pipe = self.child(directory, code, timeout=2)
            try:
                for identifier in (1, 2, 3):
                    self.assertEqual(pipe.answer({"id": identifier}), {"id": identifier, "status": 412})
                self.assertEqual((pipe.calls, pipe.conflicts), (3, 3))
            finally: pipe.close()
            self.assertIsNotNone(pipe.process.poll())


if __name__ == "__main__": unittest.main()
