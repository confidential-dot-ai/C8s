"""Whether the mesh proxy's last CA refresh succeeded.

stdin: the proxy's log with timestamps; argv: the poll interval and the
container's start. Prints ok, failed or wait, then the seconds until the
next tick has had time to be logged.
"""
import datetime
import re
import sys


def ts(s):
    s = re.sub(r"\.\d+", "", s.rstrip("Z"))
    return datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=datetime.timezone.utc).timestamp()


units = {"h": 3600, "m": 60, "s": 1}
interval = sum(int(n) * units[u] for n, u in re.findall(r"(\d+)([hms])", sys.argv[1]))
anchor, failures = ts(sys.argv[2]), []
for line in sys.stdin:
    stamp, _, msg = line.partition(" ")
    if "CA bundle refresh enabled" in msg:
        anchor, failures = ts(stamp), []
    elif "CA bundle refresh failed" in msg:
        failures.append(ts(stamp))
margin = 35  # a refresh is logged within --cds-op-timeout (30s) of its tick
now = datetime.datetime.now(datetime.timezone.utc).timestamp()
ticks = int((now - anchor - margin) // interval)
nxt = anchor + (ticks + 1) * interval + margin
if ticks < 1:
    print("wait", max(1, int(nxt - now)))
else:
    last = anchor + ticks * interval
    print("failed" if any(f >= last - 1 for f in failures) else "ok", max(1, int(nxt - now)))
