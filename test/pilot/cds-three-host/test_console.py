import sys
import tempfile
import time
import unittest
from pathlib import Path

from console import Capture


class ConsoleCapture(unittest.TestCase):
    def test_retains_bounded_tail_and_final_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'console.log'
            capture = Capture([sys.executable, '-c',
                "import sys; sys.stdout.buffer.write(b'x'*65536+b'last failure\\n')"], path, limit=1024)
            capture.process.wait(timeout=10)
            capture.close()
            self.assertEqual(path.read_bytes(), b'x'*(1024-13)+b'last failure\n')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertFalse(capture.writer.is_alive())

    def test_input_is_a_terminal_but_receives_no_keystrokes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'console.log'
            capture = Capture([sys.executable, '-u', '-c',
                "import os; print('tty='+str(os.isatty(0))); os.read(0,1); print('input received')"], path)
            try:
                end = time.monotonic()+5
                while time.monotonic() < end and b'tty=True' not in path.read_bytes():
                    time.sleep(.02)
                self.assertIn(b'tty=True', path.read_bytes())
                self.assertIsNone(capture.process.poll())
            finally:
                capture.close()
            self.assertNotIn(b'input received', path.read_bytes())
            self.assertFalse(capture.writer.is_alive())

    def test_reconnect_retains_tail_but_requires_a_new_handshake(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'console.log'
            first = Capture([sys.executable, '-u', '-c',
                "print('Successfully connected to old console'); print('previous failure')"], path, limit=1024)
            first.wait_connected(); first.process.wait(timeout=5); first.close()
            waiting = Capture([sys.executable, '-u', '-c',
                "import time; print('still connecting'); time.sleep(60)"], path, limit=1024, resume=True)
            try:
                with self.assertRaises(RuntimeError): waiting.wait_connected(timeout=.05)
            finally:
                waiting.close()
            last = Capture([sys.executable, '-u', '-c',
                "print('Successfully connected to new console'); print('new failure')"], path, limit=1024, resume=True)
            last.wait_connected(); last.process.wait(timeout=5); last.close()
            tail = path.read_bytes()
            self.assertLessEqual(len(tail), 1024)
            self.assertIn(b'previous failure', tail)
            self.assertIn(b'output may have a gap', tail)
            self.assertIn(b'new failure', tail)

    def test_console_cannot_follow_a_different_guest_uid(self):
        import run
        runner = object.__new__(run.Run)
        runner.current = lambda row: None
        runner.state = {'guest_placements': [{'vm_uid': 'owned-vm', 'vmi_uid': 'owned-guest'}]}
        class API:
            def call(self, *args): return 200, {'metadata': {'uid': 'replacement-guest'}}
        runner.kube = API()
        with self.assertRaisesRegex(ValueError, 'guest identity changed'):
            runner.start_console({'uid': 'owned-vm', 'item': {'metadata': {'name': 'owned-test'}}})


if __name__ == '__main__':
    unittest.main()
