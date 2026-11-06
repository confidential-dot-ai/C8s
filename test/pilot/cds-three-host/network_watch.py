"""Decide when an owned qualification must stop from existing pinger samples.

Historical window peaks remain evidence, but are not independent observations.
This monitor owns its state serially; it does not send probes or mutate a cluster.
"""
import math


class NetworkWatch:
    def __init__(self, expected_links, started_epoch):
        self.expected = frozenset(expected_links)
        if len(self.expected) != 6:
            raise ValueError('six directed worker links required')
        self.started = started_epoch
        self.latest = {}
        self.strikes = {}
        self.missing = 0

    def unavailable(self):
        self.missing += 1
        return {'stop': self.missing >= 2, 'reason': 'network observations unavailable twice',
                'missing_observations': self.missing}

    def observe(self, report):
        links = [(p['source'], link) for p in report['peers'] for link in p.get('links', [])]
        loss = [{'source': source, 'target': link['target'], **row}
                for source, link in links for row in link['rows']
                if row['epoch'] >= self.started and row['lost'] > 0]
        if loss:
            return {'stop': True, 'reason': 'new shared-network packet loss', 'new_loss': loss}
        keys = [(source, link['target']) for source, link in links]
        if len(keys) != len(self.expected) or set(keys) != self.expected:
            return self.unavailable()
        observations = []
        for source, link in links:
            rows = link['rows']
            # The caller already required baseline coverage before creating
            # resources. Log rotation may shorten a window while new readings
            # continue; only fresh per-link coverage matters during the run.
            if (not rows or link['last_age_seconds'] is None or
                    not -5 <= link['last_age_seconds'] <= 90):
                return self.unavailable()
            row = max(rows, key=lambda r: r['epoch'])
            key = source, link['target']
            if (not math.isfinite(row['mean_ms']) or row['mean_ms'] < 0 or
                    not math.isfinite(row['epoch']) or row['epoch'] < self.latest.get(key, float('-inf'))):
                return self.unavailable()
            observations.append((key, row))
        self.missing = 0
        for key, row in observations:
            if row['epoch'] == self.latest.get(key):
                continue  # One sample in overlapping windows is still one sample.
            self.latest[key] = row['epoch']
            self.strikes[key] = self.strikes.get(key, 0)+1 if row['mean_ms'] > 50 else 0
        elevated = [{'source': key[0], 'target': key[1], 'fresh_observations': count}
                    for key, count in sorted(self.strikes.items()) if count >= 2]
        return {'stop': bool(elevated), 'reason': 'probe latency elevated in two fresh observations',
                'elevated_links': elevated, 'missing_observations': 0}
