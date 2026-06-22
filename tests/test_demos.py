"""Verify every shipped demo behaves exactly as its SCENARIO documents.

Each demo is a real JSONL log; this asserts the documented finding/exit
outcome actually fires, so the demos can never silently rot.

No network. Standard library only.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from exfilwatch import parse_log, analyze

DEMOS = os.path.join(os.path.dirname(__file__), "..", "demos")


def _analyze(name, **kw):
    path = os.path.join(DEMOS, name, "events.jsonl")
    with open(path, "r", encoding="utf-8") as fh:
        events = parse_log(fh.read().splitlines())
    return events, analyze(events, **kw)


class TestDemos(unittest.TestCase):
    def _dsts(self, findings, detector=None):
        return {f.dst for f in findings if detector is None or f.detector == detector}

    def test_01_basic_tunnel_and_beacon(self):
        _, f = _analyze("01-basic")
        self.assertIn("evil-tunnel.example.net", self._dsts(f, "long_dns"))
        self.assertIn("cdn-metrics.example.io", self._dsts(f, "beaconing"))

    def test_02_clean_has_no_findings(self):
        _, f = _analyze("02-clean")
        self.assertEqual(f, [])

    def test_03_mixed_beacon_found_noise_ignored(self):
        _, f = _analyze("03-mixed")
        beacons = self._dsts(f, "beaconing")
        self.assertIn("telemetry-sync.example.org", beacons)
        self.assertNotIn("www.example.com", beacons)

    def test_04_dns_tunnel_entropy_and_longdns(self):
        _, f = _analyze("04-dns-tunnel-bulk")
        self.assertIn("tunnel.dataexfil.example.net", self._dsts(f, "long_dns"))
        self.assertIn("tunnel.dataexfil.example.net", self._dsts(f, "entropy"))

    def test_05_http_beacon_high_severity(self):
        _, f = _analyze("05-http-beacon-jitter")
        beacons = [x for x in f if x.detector == "beaconing"]
        self.assertTrue(beacons)
        self.assertEqual(beacons[0].severity, "high")

    def test_06_iso8601_parses_and_flags(self):
        events, f = _analyze("06-iso8601-timestamps")
        self.assertTrue(all(e.ts > 0 for e in events))  # ISO strings parsed
        self.assertIn("beacon-host.example.com", self._dsts(f, "entropy"))

    def test_07_http_path_exfil_entropy(self):
        _, f = _analyze("07-http-path-exfil")
        ent = [x for x in f if x.detector == "entropy"]
        self.assertTrue(ent)
        self.assertEqual(ent[0].dst, "assets.metrics-collect.example.io")

    def test_08_fanout_four_beaconing_hosts(self):
        _, f = _analyze("08-multi-host-fanout")
        srcs = {x.src for x in f
                if x.detector == "beaconing"
                and x.dst == "sync.shadow-update.example.net"}
        self.assertEqual(srcs, {"10.30.2.11", "10.30.2.12", "10.30.2.13", "10.30.2.14"})

    def test_09_stdin_sample_fires(self):
        _, f = _analyze("09-stdin-pipe")
        self.assertIn("exfil-ns.example.net", self._dsts(f, "beaconing"))

    def test_10_clean_at_default_fp_when_tuned_low(self):
        _, default = _analyze("10-tuning-fp")  # default entropy 3.5
        self.assertEqual(default, [])
        _, lowered = _analyze("10-tuning-fp", entropy_threshold=2.8)
        self.assertTrue(any(x.detector == "entropy" for x in lowered))


if __name__ == "__main__":
    unittest.main()
