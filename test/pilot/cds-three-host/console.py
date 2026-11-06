"""Read-only console capture with one bounded writer per owned guest."""
import os
import queue
import subprocess
import threading


class Capture:
    def __init__(self, argv, path, limit=1024*1024, resume=False):
        if limit <= 0:
            raise ValueError('positive console limit required')
        flags = os.O_RDWR | os.O_NOFOLLOW
        if not resume: flags |= os.O_CREAT | os.O_EXCL
        log = os.fdopen(os.open(path, flags, 0o600), 'r+b')
        self.master, slave = os.openpty()
        self.error = None
        self.ready = queue.Queue(maxsize=1)
        try:
            # Keep a terminal open for virtctl without ever writing a byte to
            # it. A /dev/null stdin ends an interactive console immediately.
            self.process = subprocess.Popen(argv, stdin=slave, stdout=subprocess.PIPE,
                                            stderr=subprocess.STDOUT)
        except BaseException:
            os.close(self.master); log.close(); raise
        finally:
            os.close(slave)
        self.writer = threading.Thread(target=self.drain, args=(log, limit, resume), daemon=True)
        self.writer.start()

    def drain(self, log, limit, resume):
        # This actor alone owns the tail and file; the pipe supplies
        # backpressure and both retained memory and disk usage are bounded.
        tail = bytearray()
        marker = b'Successfully connected to '
        prefix = b''
        announced = False
        try:
            with log, self.process.stdout as stream:
                if resume:
                    log.seek(0, os.SEEK_END)
                    log.seek(-min(log.tell(), limit), os.SEEK_END)
                    tail.extend(log.read(limit))
                    tail.extend(b'\n[console reconnect; output may have a gap]\n')
                while data := stream.read1(8192):
                    if not announced:
                        prefix += data
                        if marker in prefix:
                            self.ready.put_nowait(True); announced = True
                        prefix = prefix[-len(marker):]
                    tail.extend(data)
                    if len(tail) > limit:
                        del tail[:-limit]
                    log.seek(0); log.write(tail); log.truncate(); log.flush()
        except Exception as error:
            self.error = error
        finally:
            if not announced: self.ready.put_nowait(False)

    def wait_connected(self, timeout=15):
        try:
            connected = self.ready.get(timeout=timeout)
        except queue.Empty as error:
            raise RuntimeError('read-only console did not connect within its budget') from error
        if not connected:
            raise RuntimeError('read-only console exited before connecting; inspect private tail')

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
