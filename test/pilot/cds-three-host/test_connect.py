"""Exercise urllib's actual CONNECT path: no API authorization/body is sent."""
import http.server
import threading
import unittest
import urllib.error
import urllib.request
from api import ReadBackoff


class ConnectDispatch(unittest.TestCase):
    def test_rejected_connect_never_sends_origin_post(self):
        requests = []; trailing = []
        class Proxy(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_CONNECT(self):
                requests.append((self.command, dict(self.headers)))
                self.send_response(502); self.end_headers()
                self.wfile.flush()
                self.connection.settimeout(2)
                trailing.append(self.rfile.read(1))
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Proxy)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({'https': f'http://127.0.0.1:{server.server_port}'}))
            delays = []; notices = []
            retry = ReadBackoff(opener, lambda *args: notices.append(args), delays.append)
            request = urllib.request.Request('https://cds-fixture.invalid/owned-resource', data=b'never-forward-this-body',
                headers={'Authorization': 'synthetic-origin-credential'}, method='POST')
            with self.assertRaises(urllib.error.URLError): retry.open(request, timeout=2)
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=3)
        self.assertEqual(len(requests), 4)
        self.assertTrue(all(method == 'CONNECT' and 'Authorization' not in headers for method, headers in requests))
        self.assertEqual(trailing, [b'']*4)
        self.assertEqual(delays, [1, 2, 4])
        self.assertEqual(notices, [(i, delay, 'POST', 'proxy_connect') for i, delay in enumerate(delays, 1)])


if __name__ == '__main__': unittest.main()
