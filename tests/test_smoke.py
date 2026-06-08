"""Smoke + unit tests for EXFILWATCH. No network. Standard library only.

Run:  python -m unittest discover -s tests
"""
import io
import os
import sys
import json
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from exfilwatch import (
    TOOL_NAME,
    TOOL_VERSION,
    shannon_entropy,
    parse_log,
    analyze,
    detect_entropy,
    detect_beaconing,
    detect_long_dns,
)
from exfilwatch import cli

DEMO = os.path.join(
    os.path.dirname(__file__), "..", "demos", "01-basic", "events.jsonl"
)


class TestEntropy(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(shannon_entropy(""), 0.0)

    def test_uniform_string_low_entropy(self):
        self.assertEqual(shannon_entropy("aaaaaaaa"), 0.0)

    def test_random_higher_than_word(self):
        word = shannon_entropy("newsletter")
        rnd = shannon_entropy("mfrggzdfmztwq2lknbswg43f")
        self.assertGreater(rnd, word)


class TestParse(unittest.TestCase):
    def test_skips_comments_and_blanks(self):
        lines = ["# comment", "", '{"ts": 1, "src": "a", "dst": "b"}']
        events = parse_log(lines)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].src, "a")

    def test_iso_timestamp(self):
        events = parse_log(['{"ts": "2024-01-01T00:00:00Z", "src": "a", "dst": "b"}'])
        self.assertEqual(len(events), 1)
        self.assertGreater(events[0].ts, 0)

    def test_missing_field_raises(self):
        with self.assertRaises(ValueError):
            parse_log(['{"ts": 1, "src": "a"}'])

    def test_bad_json_raises(self):
        with self.assertRaises(ValueError):
            parse_log(["{not json}"])


class TestDetectors(unittest.TestCase):
    def setUp(self):
        with open(DEMO, "r", encoding="utf-8") as fh:
            self.events = parse_log(fh.read().splitlines())

    def test_entropy_flags_tunnel_not_benign(self):
        findings = detect_entropy(self.events)
        dsts = {f.dst for f in findings}
        self.assertIn("evil-tunnel.example.net", dsts)
        self.assertNotIn("www.example.com", dsts)

    def test_beaconing_flags_metrics(self):
        findings = detect_beaconing(self.events)
        dsts = {f.dst for f in findings}
        self.assertIn("cdn-metrics.example.io", dsts)

    def test_long_dns_flags_tunnel(self):
        findings = detect_long_dns(self.events)
        self.assertTrue(any(f.dst == "evil-tunnel.example.net" for f in findings))

    def test_analyze_sorted_and_nonempty(self):
        findings = analyze(self.events)
        self.assertGreater(len(findings), 0)
        scores = [f.score for f in findings]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_benign_only_log_clean(self):
        benign = [e for e in self.events if e.src == "10.0.0.12"]
        self.assertEqual(analyze(benign), [])


class TestCli(unittest.TestCase):
    def test_scan_demo_returns_findings_exit(self):
        rc = cli.main(["scan", DEMO])
        self.assertEqual(rc, cli.EXIT_FINDINGS)

    def test_json_format_valid_and_findings(self):
        buf = io.StringIO()
        old = sys.stdout
        sys.stdout = buf
        try:
            rc = cli.main(["scan", DEMO, "--format", "json"])
        finally:
            sys.stdout = old
        self.assertEqual(rc, cli.EXIT_FINDINGS)
        payload = json.loads(buf.getvalue())
        self.assertEqual(payload["tool"], TOOL_NAME)
        self.assertEqual(payload["version"], TOOL_VERSION)
        self.assertGreater(payload["finding_count"], 0)

    def test_missing_file_errors(self):
        rc = cli.main(["scan", "/no/such/file/exfilwatch.jsonl"])
        self.assertEqual(rc, cli.EXIT_ERROR)

    def test_clean_log_exit_ok(self):
        import tempfile
        with tempfile.NamedTemporaryFile(
            "w", suffix=".jsonl", delete=False, encoding="utf-8"
        ) as tf:
            tf.write('{"ts": 1, "src": "10.0.0.1", "dst": "www.example.com", "proto": "dns", "query": "www.example.com"}\n')
            path = tf.name
        try:
            rc = cli.main(["scan", path])
            self.assertEqual(rc, cli.EXIT_OK)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
