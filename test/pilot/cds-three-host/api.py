"""Bounded backoff for transient read-only Kubernetes API failures."""
import datetime as dt
import email.utils
import time
import urllib.error


class ReadBackoff:
    def __init__(self, opener, notice, sleep=time.sleep, monotonic=time.monotonic):
        self.opener, self.notice = opener, notice
        self.sleep, self.monotonic = sleep, monotonic

    def open(self, request, timeout=30):
        if request.get_method() != 'GET':
            return self.opener.open(request, timeout=timeout)
        deadline = self.monotonic()+75
        for attempt in range(4):
            try:
                return self.opener.open(request, timeout=min(timeout, deadline-self.monotonic()))
            except urllib.error.HTTPError as error:
                if error.code not in (429, 502, 503, 504) or attempt == 3:
                    raise
                delay = 2**attempt
                hint = error.headers.get('Retry-After', '')
                try:
                    wait = float(hint) if hint.isdigit() else (
                        email.utils.parsedate_to_datetime(hint)-dt.datetime.now(dt.timezone.utc)).total_seconds()
                    delay = max(delay, wait)
                except (TypeError, ValueError, OverflowError):
                    pass
                if delay > 30 or delay >= deadline-self.monotonic():
                    raise
                error.close()
                self.notice(attempt+1, delay)
                self.sleep(delay)
