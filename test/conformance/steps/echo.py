# The echo API a workload backend serves (routebackend.go): every request is
# answered with what it received, as JSON, under the pod's leaf, read again
# for each connection so that a renewal never leaves it serving an expired
# one. It listens once the leaf is there.
# Usage: python3 echo.py <tls.crt> <tls.key> <port>
import http.server, json, os, socket, ssl, sys, time
crt, key, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
while not (os.path.exists(crt) and os.path.exists(key)):
    time.sleep(0.5)
class Handler(http.server.BaseHTTPRequestHandler):
    def handle_one_request(self):
        self.raw_requestline = self.rfile.readline(65537)
        if not self.raw_requestline or not self.parse_request():
            return
        body = json.dumps({"pod": socket.gethostname(), "target": self.path,
                           "headers": {k.lower(): v for k, v in self.headers.items()}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()
class Server(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6 if socket.has_ipv6 else socket.AF_INET
    def get_request(self):
        sock, addr = self.socket.accept()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3  # the router's floor for a workload backend
        ctx.load_cert_chain(crt, key)
        return ctx.wrap_socket(sock, server_side=True), addr
try:
    Server(("::", port), Handler).serve_forever()
except OSError:
    Server.address_family = socket.AF_INET
    Server(("", port), Handler).serve_forever()
