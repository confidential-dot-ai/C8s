"""Bounded retry of reads and proxy CONNECT rejections before API dispatch."""
import datetime as dt
import email.utils
import re
import time
import urllib.error


class ReadBackoff:
    def __init__(self, opener, notice, sleep=time.sleep, monotonic=time.monotonic):
        self.opener, self.notice = opener, notice
        self.sleep, self.monotonic = sleep, monotonic

    def open(self, request, timeout=30):
        method = request.get_method()
        deadline = self.monotonic()+75
        for attempt in range(4):
            try:
                return self.opener.open(request, timeout=min(timeout, deadline-self.monotonic()))
            except urllib.error.URLError as error:
                # http.client._tunnel raises this OSError before sending TLS
                # or any origin HTTP headers/body. Even a mutation has not
                # reached Kubernetes. Never classify an origin HTTPError,
                # arbitrary socket error, TLS failure or proxy denial this way.
                connect = not isinstance(error, urllib.error.HTTPError) and isinstance(error.reason, OSError) and bool(
                    re.fullmatch(r'Tunnel connection failed: (502|503|504) [^\r\n]*', str(error.reason)))
                read = method == 'GET' and isinstance(error, urllib.error.HTTPError) and error.code in (429, 502, 503, 504)
                if not (connect or read) or attempt == 3:
                    raise
                delay = 2**attempt
                hint = error.headers.get('Retry-After', '') if read else ''
                try:
                    wait = float(hint) if hint.isdigit() else (
                        email.utils.parsedate_to_datetime(hint)-dt.datetime.now(dt.timezone.utc)).total_seconds()
                    delay = max(delay, wait)
                except (TypeError, ValueError, OverflowError):
                    pass
                if delay > 30 or delay >= deadline-self.monotonic():
                    raise
                if isinstance(error, urllib.error.HTTPError): error.close()
                self.notice(attempt+1, delay, method, 'proxy_connect' if connect else 'http_read')
                self.sleep(delay)
