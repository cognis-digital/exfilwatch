"""Tests for the SARIF 2.1.0 export and the HTTP host-skip entropy fix.

No network. Standard library only.
"""
import io
import os
import sys
import json
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from exfilwatch import parse_log, analyze, detect_entropy
from exfilwatch.core import to_sarif, LogEvent
from exfilwatch import cli

DEMO = os.path.join(os.path.dirname(__file__), "..", "demos", "01-basic", "events.jsonl")


def _load(path):
    with open(path, "r", encoding="utf-8") as fh:
        return parse_log(fh.read().splitlines())


class TestSarif(unittest.TestCase):
    def setUp(self):
        self.findings = analyze(_load(DEMO))

    def test_envelope_is_sarif_210(self):
        doc = to_sarif(self.findings)
        self.assertEqual(doc["version"], "2.1.0")
        self.assertIn("$schema", doc)
        self.assertEqual(len(doc["runs"]), 1)

    def test_one_result_per_finding(self):
        doc = to_sarif(self.findings)
        results = doc["runs"][0]["results"]
        self.assertEqual(len(results), len(self.findings))

    def test_levels_map_from_severity(self):
        # craft findings of each severity and confirm SARIF level mapping
        from exfilwatch.core import Finding
        fs = [
            Finding("entropy", "high", "a", "b", 0.9, "x"),
            Finding("beaconing", "medium", "a", "b", 0.6, "x"),
            Finding("long_dns", "low", "a", "b", 0.3, "x"),
        ]
        levels = [r["level"] for r in to_sarif(fs)["runs"][0]["results"]]
        self.assertEqual(levels, ["error", "warning", "note"])

    def test_rules_present_and_referenced(self):
        doc = to_sarif(self.findings)
        rules = doc["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = {r["id"] for r in rules}
        self.assertEqual(rule_ids, {"EXF-ENTROPY", "EXF-BEACON", "EXF-LONGDNS"})
        for r in doc["runs"][0]["results"]:
            self.assertIn(r["ruleId"], rule_ids)

    def test_log_uri_recorded(self):
        doc = to_sarif(self.findings, log_uri="path/to/net.jsonl")
        loc = doc["runs"][0]["results"][0]["locations"][0]
        uri = loc["physicalLocation"]["artifactLocation"]["uri"]
        self.assertEqual(uri, "path/to/net.jsonl")

    def test_serializable(self):
        # must round-trip as JSON (no datetime / set leakage)
        json.dumps(to_sarif(self.findings))

    def test_cli_sarif_output(self):
        buf = io.StringIO()
        old = sys.stdout
        sys.stdout = buf
        try:
            rc = cli.main(["scan", DEMO, "--format", "sarif"])
        finally:
            sys.stdout = old
        self.assertEqual(rc, cli.EXIT_FINDINGS)
        doc = json.loads(buf.getvalue())
        self.assertEqual(doc["version"], "2.1.0")
        self.assertGreater(len(doc["runs"][0]["results"]), 0)


class TestHttpHostSkip(unittest.TestCase):
    """A normal FQDN in an HTTP URL must not, by itself, raise an entropy flag."""

    def test_benign_hostname_not_flagged(self):
        evs = [
            LogEvent(ts=float(i), src="10.0.0.1", dst="updates.example.com",
                     proto="http",
                     query="https://updates.example.com/index.html")
            for i in range(5)
        ]
        self.assertEqual(detect_entropy(evs), [])

    def test_high_entropy_path_still_flagged(self):
        evs = [
            LogEvent(ts=float(i), src="10.0.0.1", dst="c2.example.io",
                     proto="http",
                     query="https://c2.example.io/upload/MFRGGZDFMZTWQ2LKNBSWG43F" + str(i))
            for i in range(5)
        ]
        findings = detect_entropy(evs)
        self.assertTrue(any(f.detector == "entropy" for f in findings))


if __name__ == "__main__":
    unittest.main()
