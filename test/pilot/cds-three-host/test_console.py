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


if __name__ == '__main__':
    unittest.main()
