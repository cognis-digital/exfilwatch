"""Offline tests for the threat-intel enrichment layer (feodo-c2 + threatfox).

These tests NEVER touch the network: COGNIS_FEEDS_CACHE is pointed at the
committed trimmed fixtures and every feed read uses offline=True. This is the
exact edge / air-gap path the tool runs on disconnected gear.

Standard library only.
"""
import os
import sys
import json
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

FIXTURE_CACHE = os.path.join(os.path.dirname(__file__), "fixtures", "feeds-cache")
# Point the datafeeds cache at our committed fixtures BEFORE importing anything
# that resolves the cache dir.
os.environ["COGNIS_FEEDS_CACHE"] = FIXTURE_CACHE

from exfilwatch import feeds as fx
from exfilwatch import parse_log, analyze
from exfilwatch import cli

DEMOS = os.path.join(os.path.dirname(__file__), "..", "demos")
DEMO_LOG = os.path.join(DEMOS, "11-c2-attribution", "events.jsonl")

# deterministic indicators present in the committed fixtures
KNOWN_C2_IP = "185.244.25.231"          # Feodo / Emotet, status online
KNOWN_C2_DOMAIN = "evil-exfil.example.com"  # ThreatFox / Cobalt Strike


class TestFixturesPresent(unittest.TestCase):
    def test_fixture_cache_exists(self):
        for fid in fx.FEED_IDS:
            self.assertTrue(os.path.exists(os.path.join(FIXTURE_CACHE, fid + ".data")),
                            f"missing fixture for {fid}")


class TestIndex(unittest.TestCase):
    def setUp(self):
        self.index = fx.build_index(offline=True)

    def test_known_c2_ip_indexed(self):
        self.assertIn(KNOWN_C2_IP, self.index)
        hit = self.index[KNOWN_C2_IP][0]
        self.assertEqual(hit.feed, "feodo-c2")
        self.assertEqual(hit.malware, "Emotet")
        self.assertEqual(hit.indicator_type, "ip")
        self.assertEqual(hit.confidence, 100)

    def test_known_c2_domain_indexed(self):
        self.assertIn(KNOWN_C2_DOMAIN, self.index)
        hit = self.index[KNOWN_C2_DOMAIN][0]
        self.assertEqual(hit.feed, "threatfox")
        self.assertEqual(hit.malware, "Cobalt Strike")
        self.assertEqual(hit.indicator_type, "domain")
        self.assertGreaterEqual(hit.confidence, 90)

    def test_index_stats(self):
        stats = fx.index_stats(self.index)
        self.assertGreaterEqual(stats["ip_hits"], 1)
        self.assertGreaterEqual(stats["domain_hits"], 1)

    def test_offline_missing_raises(self):
        # an unknown-but-allowed-shaped call with empty cache dir would raise;
        # here we assert a feed id outside the allow-list is rejected.
        with self.assertRaises(ValueError):
            fx.build_index(offline=True, feed_ids=("cisa-kev",))


class TestEnrich(unittest.TestCase):
    def _findings(self):
        with open(DEMO_LOG, "r", encoding="utf-8") as fh:
            events = parse_log(fh.read().splitlines())
        return analyze(events)

    def test_enrich_attributes_known_c2(self):
        findings = self._findings()
        matches = fx.enrich(findings, offline=True)
        self.assertIn(KNOWN_C2_IP, matches)
        self.assertIn(KNOWN_C2_DOMAIN, matches)

    def test_enrich_bumps_severity_and_evidence(self):
        findings = self._findings()
        fx.enrich(findings, offline=True)
        c2 = [f for f in findings if f.dst == KNOWN_C2_IP]
        self.assertTrue(c2)
        f = c2[0]
        self.assertEqual(f.severity, "high")
        self.assertGreaterEqual(f.score, 0.99)
        self.assertIn("intel", f.evidence)
        self.assertIn("Emotet", f.evidence.get("intel_malware", []))
        self.assertIn("KNOWN C2", f.summary)

    def test_clean_destination_not_matched(self):
        findings = self._findings()
        matches = fx.enrich(findings, offline=True)
        self.assertNotIn("cdn.legit-service.example", matches)


class TestCli(unittest.TestCase):
    def test_feeds_list(self):
        rc = cli.main(["feeds", "list"])
        self.assertEqual(rc, 0)

    def test_feeds_get_offline(self):
        rc = cli.main(["feeds", "get", "feodo-c2", "--offline"])
        self.assertEqual(rc, 0)

    def test_feeds_rejects_foreign_id(self):
        rc = cli.main(["feeds", "get", "cisa-kev", "--offline"])
        self.assertEqual(rc, cli.EXIT_ERROR)

    def test_scan_enrich_offline_exit_findings(self):
        rc = cli.main(["scan", DEMO_LOG, "--enrich", "--offline"])
        self.assertEqual(rc, cli.EXIT_FINDINGS)

    def test_scan_enrich_offline_json(self):
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli.main(["scan", DEMO_LOG, "--enrich", "--offline", "--format", "json"])
        self.assertEqual(rc, cli.EXIT_FINDINGS)
        payload = json.loads(buf.getvalue())
        self.assertIn("intel_matches", payload)
        self.assertIn(KNOWN_C2_IP, payload["intel_matches"])


if __name__ == "__main__":
    unittest.main()
