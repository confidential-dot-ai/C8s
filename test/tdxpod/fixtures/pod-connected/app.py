#!/usr/bin/env python3
"""Pinned Pod-CVM acceptance workload; all networking uses the stdlib."""
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
import secrets
import socket
import ssl
import struct
import sys
import threading
import time
import urllib.parse

CONFIG = json.loads(sys.argv[1])
INSTANCE = secrets.token_hex(16)
START = time.monotonic()
LOCK = threading.Lock()
STATE = {"instance": INSTANCE, "checks": {}, "firstPass": None, "checkedAt": None}


def exact(sock, size):
    data = b""
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise RuntimeError("short DNS response")
        data += part
    return data


def dns_wire(network):
    ident = secrets.randbelow(65536)
    name = b"".join(bytes([len(p)]) + p.encode() for p in "example.com".split(".")) + b"\0"
    query = struct.pack("!6H", ident, 0x100, 1, 0, 0, 0) + name + struct.pack("!2H", 1, 1)
    kind = socket.SOCK_STREAM if network == "tcp" else socket.SOCK_DGRAM
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.settimeout(4)
        sock.connect((CONFIG["dnsIPv4"], 53))
        if network == "tcp":
            sock.sendall(struct.pack("!H", len(query)) + query)
            size = struct.unpack("!H", exact(sock, 2))[0]
            if not 12 <= size <= 8192:
                raise RuntimeError("invalid DNS response length")
            reply = exact(sock, size)
        else:
            sock.send(query)
            reply = sock.recv(8192)
    header = struct.unpack("!6H", reply[:12])
    if header[0] != ident or not header[1] & 0x8000 or header[1] & 15 or header[3] == 0:
        raise RuntimeError("DNS response did not answer the query")
    return {"resolver": CONFIG["dnsIPv4"], "answers": header[3]}


def system_dns():
    addresses = sorted({item[4][0] for item in socket.getaddrinfo("example.com", 443, socket.AF_INET)})
    resolvers = [line.split()[1] for line in open("/etc/resolv.conf", encoding="utf-8")
                 if line.startswith("nameserver ")]
    if not addresses or not resolvers:
        raise RuntimeError("no system DNS result or resolver")
    for value in resolvers:
        address = ipaddress.ip_address(value)
        if address.is_loopback or address.is_link_local or value == "10.255.254.1":
            raise RuntimeError("guest-local DNS configuration")
    return {"addresses": addresses, "resolvers": resolvers}


def internet_tcp():
    conn = http.client.HTTPSConnection("example.com", timeout=5, context=ssl.create_default_context())
    try:
        conn.request("GET", "/")
        response = conn.getresponse()
        response.read(512)
        if not 200 <= response.status < 400:
            raise RuntimeError("internet HTTPS status " + str(response.status))
        return {"status": response.status}
    finally:
        conn.close()


def peer_mesh():
    found = []
    for host in CONFIG["peers"]:
        conn = http.client.HTTPConnection(host, 8080, timeout=4)
        try:
            conn.request("GET", "/id")
            response = conn.getresponse()
            body = json.loads(response.read(4096))
            if response.status == 200 and body["instance"] != INSTANCE:
                found.append({"endpoint": host + ":8080", "instance": body["instance"]})
        except (OSError, ValueError, KeyError, http.client.HTTPException):
            pass
        finally:
            conn.close()
    if not found:
        raise RuntimeError("no distinct peer answered through the captured tuple")
    return found


def exclusions():
    results = []
    for host, port in [("10.255.254.1", 8443), ("10.255.254.1", 8400),
                       ("10.255.254.1", 10250), ("169.254.169.254", 80)]:
        try:
            with socket.create_connection((host, port), timeout=1):
                raise RuntimeError("forbidden destination is reachable: " + host + ":" + str(port))
        except OSError as error:
            results.append({"destination": host + ":" + str(port), "result": type(error).__name__})
    return results


def report():
    with LOCK:
        result = dict(STATE)
    elapsed = time.monotonic() - START
    passed = result["firstPass"]
    age = elapsed - passed if passed is not None else -1
    checked = result.get("checkedAt")
    result.update({"elapsed": round(elapsed, 2), "uid": os.getuid(), "podUID": CONFIG["podUID"],
                   "ready": bool(result["checks"]) and all(v["ok"] for v in result["checks"].values())
                   and checked is not None and 0 <= elapsed - checked <= 90
                   and age >= 120 and not 300 <= age < 480})
    return result


def probe_loop():
    checks = {"peer_mesh": peer_mesh, "system_dns": system_dns, "internet_tcp": internet_tcp,
              "internet_udp_dns": lambda: dns_wire("udp"), "internet_tcp_dns": lambda: dns_wire("tcp"),
              "guest_linklocal_denied": exclusions}
    while True:
        results = {}
        for name, check in checks.items():
            try:
                results[name] = {"ok": True, "detail": check()}
            except Exception as error:
                results[name] = {"ok": False, "error": type(error).__name__ + ": " + str(error)[:200]}
        with LOCK:
            STATE["checks"] = results
            STATE["checkedAt"] = time.monotonic() - START
            if STATE["firstPass"] is None and all(value["ok"] for value in results.values()):
                STATE["firstPass"] = time.monotonic() - START
        body = json.dumps(report(), sort_keys=True).encode()
        print(body.decode(), flush=True)
        if CONFIG.get("collectorURL"):
            endpoint = urllib.parse.urlsplit(CONFIG["collectorURL"])
            conn = http.client.HTTPConnection(endpoint.hostname, endpoint.port or 80, timeout=3)
            try:
                conn.request("POST", endpoint.path or "/", body, {"Content-Type": "application/json"})
                conn.getresponse().read(256)
            except (OSError, http.client.HTTPException):
                pass
            finally:
                conn.close()
        time.sleep(15)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        status = 200
        body = {"instance": INSTANCE}
        if self.path == "/ready":
            body = report()
            status = 200 if body["ready"] else 503
        elif self.path == "/report":
            body = report()
        elif self.path not in ("/id", "/live"):
            status, body = 404, {}
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_):
        pass


def checker():
    """Exit status is the result consumed through authenticated pod-status."""
    initial_ready = forced_false = recovered = False
    deadline = START + 5400
    while time.monotonic() < deadline:
        conn = http.client.HTTPConnection("127.0.0.1", 8080, timeout=3)
        try:
            conn.request("GET", "/report")
            response = conn.getresponse()
            state = json.loads(response.read(32768))
            if response.status != 200 or state.get("podUID") != CONFIG["podUID"]:
                raise ValueError("unexpected local application report")
            passed = state.get("firstPass")
            if passed is None:
                if time.monotonic() - START > 1200:
                    print("initial network acceptance timed out", flush=True)
                    return 10
            else:
                age = state["elapsed"] - passed
                checks = state.get("checks", {})
                checked = state.get("checkedAt")
                healthy = (len(checks) == 6 and all(value.get("ok") is True for value in checks.values())
                           and checked is not None and 0 <= state["elapsed"] - checked <= 90)
                if healthy and 120 <= age < 300 and state.get("ready"):
                    initial_ready = True
                if healthy and 300 <= age < 480 and not state.get("ready"):
                    forced_false = True
                if healthy and age >= 480 and state.get("ready"):
                    recovered = True
                if age >= 700 and not (initial_ready and forced_false and recovered):
                    print("readiness transition acceptance failed", flush=True)
                    return 11
                if age >= 3900 and healthy and initial_ready and forced_false and recovered:
                    print(json.dumps({"result": "pass", "elapsedAfterInitialPass": age,
                                      "instance": state["instance"], "checks": checks}), flush=True)
                    return 0
        except (OSError, ValueError, KeyError, TypeError, http.client.HTTPException):
            pass
        finally:
            conn.close()
        time.sleep(10)
    print("post-soak network acceptance timed out", flush=True)
    return 12


if __name__ == "__main__":
    if CONFIG.get("mode") == "checker":
        sys.exit(checker())
    server = ThreadingHTTPServer(("0.0.0.0", 8080), Handler)
    threading.Thread(target=probe_loop, daemon=True).start()
    server.serve_forever()
