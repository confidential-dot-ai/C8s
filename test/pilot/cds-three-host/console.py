"""Read-only console capture with one bounded writer per owned guest."""
import os
import subprocess
import threading


class Capture:
    def __init__(self, argv, path, limit=1024*1024):
        if limit <= 0:
            raise ValueError('positive console limit required')
        log = os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb')
        self.master, slave = os.openpty()
        self.error = None
        try:
            # Keep a terminal open for virtctl without ever writing a byte to
            # it. A /dev/null stdin ends an interactive console immediately.
            self.process = subprocess.Popen(argv, stdin=slave, stdout=subprocess.PIPE,
                                            stderr=subprocess.STDOUT)
        except BaseException:
            os.close(self.master); log.close(); raise
        finally:
            os.close(slave)
        self.writer = threading.Thread(target=self.drain, args=(log, limit), daemon=True)
        self.writer.start()

    def drain(self, log, limit):
        # This actor alone owns the tail and file; the pipe supplies
        # backpressure and both retained memory and disk usage are bounded.
        tail = bytearray()
        try:
            with log, self.process.stdout as stream:
                while data := stream.read1(8192):
                    tail.extend(data)
                    if len(tail) > limit:
                        del tail[:-limit]
                    log.seek(0); log.write(tail); log.truncate(); log.flush()
        except Exception as error:
            self.error = error

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill(); self.process.wait(timeout=5)
        os.close(self.master)
        self.writer.join(timeout=5)
        if self.writer.is_alive() or self.error:
            raise RuntimeError('bounded console writer did not finish cleanly') from self.error
