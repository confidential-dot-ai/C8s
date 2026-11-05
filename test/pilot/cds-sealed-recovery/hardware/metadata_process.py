"""Bounded, single-owner pipe to the real metadata pilot; no retry on ambiguity."""
import json
import os
from pathlib import Path
import select
import subprocess
import time


class MetadataProcess:
    LIMIT = 3 * 1024**2

    def __init__(self, executable, database, namespace, errors, timeout=6):
        self.timeout = timeout
        self.calls = self.conflicts = 0
        self.closed = False
        self.process = subprocess.Popen([str(Path(executable).resolve()), "-db", str(database),
            "-namespace", namespace], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=errors, bufsize=0)
        os.set_blocking(self.process.stdin.fileno(), False)
        os.set_blocking(self.process.stdout.fileno(), False)

    def ready(self, deadline, writing=False):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("native metadata pipe deadline; commit may be ambiguous")
        reads, writes, _ = select.select([] if writing else [self.process.stdout],
            [self.process.stdin] if writing else [], [], remaining)
        if not (writes if writing else reads):
            raise TimeoutError("native metadata pipe deadline; commit may be ambiguous")

    def answer(self, request):
        if self.closed:
            raise RuntimeError("native metadata pipe is closed")
        try:
            body = json.dumps(request, separators=(",", ":")).encode() + b"\n"
            if len(body) > self.LIMIT:
                raise RuntimeError("native metadata pipe request exceeds bound")
            deadline, position = time.monotonic() + self.timeout, 0
            while position < len(body):
                self.ready(deadline, writing=True)
                try: position += os.write(self.process.stdin.fileno(), body[position:position+65536])
                except BlockingIOError: pass
            response = bytearray()
            while not response.endswith(b"\n"):
                self.ready(deadline)
                try: chunk = os.read(self.process.stdout.fileno(), 65536)
                except BlockingIOError: continue
                if not chunk:
                    raise RuntimeError("native metadata pipe exited; commit may be ambiguous")
                response.extend(chunk)
                if len(response) > self.LIMIT:
                    raise RuntimeError("native metadata pipe response exceeds bound")
            value = json.loads(response)
            if not isinstance(value, dict) or value.get("id") != request["id"] or value.get("status") not in (200, 204, 400, 403, 409, 412, 429, 503):
                raise RuntimeError("native metadata pipe returned an invalid response")
            self.calls += 1
            self.conflicts += value["status"] == 412
            return value
        except BaseException:
            # A lost commit reply must never become a transparent re-execution.
            self.close()
            raise

    def close(self):
        if self.closed: return
        self.closed = True
        self.process.stdin.close()
        try: self.process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            try: self.process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)
        self.process.stdout.close()
