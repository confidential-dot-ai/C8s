import base64
import http.client
import http.server
import queue
import threading
from pathlib import Path
import tempfile
import subprocess
import tarfile
import unittest

from integrated import DurableObjects, Integrated


class DurableStoreTests(unittest.TestCase):
    def test_ack_survives_reopen_and_cas_never_overwrites_wrong_version(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "objects.sqlite"
            store = DurableObjects(path, "test")
            q = {"id": 1, "method": "PUT", "path": "/pilot/test/head", "absent": "*", "data": base64.b64encode(b"encrypted").decode()}
            answer = store.answer(q)
            self.assertEqual(answer["status"], 200)
            store.close()
            store = DurableObjects(path, "test")
            self.assertEqual(store.answer(q)["status"], 412)
            q.pop("absent")
            q["match"] = '"wrong"'
            self.assertEqual(store.answer(q)["status"], 412)
            q["match"] = answer["etag"]
            self.assertEqual(store.answer(q)["status"], 200)
            got = store.answer({"id": 2, "method": "GET", "path": q["path"]})
            self.assertEqual(base64.b64decode(got["data"]), b"encrypted")
            store.close()

    def test_scope_and_unconditional_writes_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            store = DurableObjects(Path(directory) / "objects.sqlite", "test")
            for request in ({"id": 1, "method": "GET", "path": "/pilot/other/head"},
                            {"id": 1, "method": "PUT", "path": "/pilot/test/head"},
                            {"id": 1, "method": "PUT", "path": "/pilot/test/head", "absent": "*", "match": '"1"'}):
                with self.assertRaises(RuntimeError): store.answer(request)
            store.close()


class LocalUpload(Integrated):
    def __init__(self, directory, corrupt=False):
        self.directory = directory
        self.events = []
        self.corrupt = corrupt

    def kubectl(self, *args):
        return list(args[args.index("--") + 1:])

    def command(self, name, argv, **kwargs):
        if self.corrupt and argv[0] == "sha256sum":
            return b"wrong digest"
        return subprocess.check_output(argv, timeout=kwargs.get("timeout", 20))

    def event(self, name, **fields):
        self.events.append((name, fields))


class ChunkUploadTests(unittest.TestCase):
    def test_extraction_requires_verified_chunks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.mkdir()
            source = root / "disk.raw"
            source.write_bytes(b"public measured artifact" * 1000)
            with tarfile.open(root / "root.tar.gz", "w:gz") as archive:
                archive.add(source, arcname="disk.img")
            failed = LocalUpload(root, corrupt=True)
            with self.assertRaises(RuntimeError):
                failed.upload("owned-pod", "root.tar.gz", str(target))
            self.assertFalse((target / "disk.img").exists())
            good = LocalUpload(root)
            good.upload("owned-pod", "root.tar.gz", str(target))
            self.assertEqual((target / "disk.img").read_bytes(), source.read_bytes())
            self.assertEqual([e[0] for e in good.events], ["upload-chunk-verified", "upload-receiver-completed"])


class TunnelKeepaliveTests(unittest.TestCase):
    def test_actor_reuses_its_tunnel_connection(self):
        observed = queue.Queue()
        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            def do_GET(self):
                observed.put(self.client_address)
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")
            def log_message(self, *args): pass
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        try:
            actor = object.__new__(Integrated)
            for _ in range(3):
                self.assertEqual(actor.http(server.server_port, "GET", "/v1/storage", connection=connection), (200, {}))
            addresses = [observed.get_nowait() for _ in range(3)]
            self.assertEqual(len(set(addresses)), 1)
        finally:
            connection.close()
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == "__main__": unittest.main()
