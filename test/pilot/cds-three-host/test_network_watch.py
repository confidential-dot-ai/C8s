import copy
import unittest

from network_watch import NetworkWatch


LINKS = {(a, b) for a in ('a', 'b', 'c') for b in ('a', 'b', 'c') if a != b}


def report(epoch=100, latest_mean=10, historical_peak=10):
    peers = []
    for source in ('a', 'b', 'c'):
        links = []
        for target in ('a', 'b', 'c'):
            if target == source: continue
            rows = [{'epoch': epoch-i*12, 'lost': 0, 'count': 3,
                     'mean_ms': latest_mean if i == 0 else historical_peak} for i in range(8)]
            links.append({'target': target, 'rows': rows, 'last_age_seconds': 2})
        peers.append({'source': source, 'links': links})
    return {'peers': peers}


class WatchTest(unittest.TestCase):
    def test_overlapping_windows_do_not_count_an_old_peak_twice(self):
        watch = NetworkWatch(LINKS, 0)
        self.assertFalse(watch.observe(report(100, 51.67))['stop'])
        self.assertFalse(watch.observe(report(100, 51.67))['stop'])
        self.assertFalse(watch.observe(report(112, 10, 51.67))['stop'])
        self.assertFalse(watch.observe(report(124, 10, 51.67))['stop'])

    def test_two_fresh_elevated_observations_stop(self):
        watch = NetworkWatch(LINKS, 0)
        self.assertFalse(watch.observe(report(100, 51))['stop'])
        self.assertTrue(watch.observe(report(132, 52))['stop'])

    def test_fresh_normal_reading_breaks_latency_streak(self):
        watch = NetworkWatch(LINKS, 0)
        for epoch, mean in ((100, 51), (132, 10), (164, 52)):
            self.assertFalse(watch.observe(report(epoch, mean))['stop'])

    def test_one_new_lost_packet_stops_even_with_incomplete_coverage(self):
        watch = NetworkWatch(LINKS, 0)
        data = report(); row = data['peers'][0]['links'][0]['rows'][0]; row['lost'] = 1
        data['peers'] = data['peers'][:1]
        result = watch.observe(data)
        self.assertTrue(result['stop']); self.assertEqual(result['new_loss'][0]['lost'], 1)

    def test_two_missing_or_stale_observations_stop(self):
        for broken in ({'peers': []}, report()):
            if broken['peers']: broken['peers'][0]['links'][0]['last_age_seconds'] = 100
            watch = NetworkWatch(LINKS, 0)
            self.assertFalse(watch.observe(broken)['stop'])
            self.assertTrue(watch.observe(copy.deepcopy(broken))['stop'])
        watch = NetworkWatch(LINKS, 0)
        self.assertFalse(watch.unavailable()['stop'])
        self.assertTrue(watch.unavailable()['stop'])

    def test_log_rotation_preserves_fresh_monitoring_but_empty_reads_fail(self):
        watch = NetworkWatch(LINKS, 0)
        self.assertFalse(watch.observe(report())['stop'])
        rotated = report(132)
        for peer in rotated['peers']:
            for link in peer['links']: link['rows'] = link['rows'][:1]
        self.assertFalse(watch.observe(rotated)['stop'])
        rotated['peers'][0]['links'][0]['rows'] = []
        self.assertFalse(watch.observe(rotated)['stop'])
        self.assertTrue(watch.observe(rotated)['stop'])


if __name__ == '__main__': unittest.main()
