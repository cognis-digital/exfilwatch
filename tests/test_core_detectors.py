"""Expanded unit tests for the core detection engine. Offline, stdlib only."""
import math
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from exfilwatch.core import (
    LogEvent,
    Finding,
    shannon_entropy,
    parse_log,
    analyze,
    detect_entropy,
    detect_beaconing,
    detect_long_dns,
    to_sarif,
    _parse_ts,
    _registrable_labels,
    _severity_from_score,
)


class TestShannonEntropy(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(shannon_entropy(""), 0.0)

    def test_single_char(self):
        self.assertEqual(shannon_entropy("xxxxx"), 0.0)

    def test_two_equal_chars_is_one_bit(self):
        self.assertAlmostEqual(shannon_entropy("ab"), 1.0)

    def test_four_equal_chars_is_two_bits(self):
        self.assertAlmostEqual(shannon_entropy("abcd"), 2.0)

    def test_monotonic_with_diversity(self):
        self.assertGreater(shannon_entropy("abcdefgh"), shannon_entropy("aabbccdd"))

    def test_base32_payload_high(self):
        self.assertGreater(shannon_entropy("mfrggzdfmztwq2lknbswg43f"), 3.5)


class TestParseTs(unittest.TestCase):
    def test_int(self):
        self.assertEqual(_parse_ts(5), 5.0)

    def test_float(self):
        self.assertEqual(_parse_ts(5.5), 5.5)

    def test_epoch_string(self):
        self.assertEqual(_parse_ts("1700000000"), 1700000000.0)

    def test_iso_z(self):
        self.assertGreater(_parse_ts("2024-01-01T00:00:00Z"), 0)

    def test_iso_offset(self):
        self.assertGreater(_parse_ts("2024-01-01T00:00:00+00:00"), 0)

    def test_garbage_raises(self):
        with self.assertRaises(ValueError):
            _parse_ts("not-a-time")

    def test_none_raises(self):
        with self.assertRaises(ValueError):
            _parse_ts(None)


class TestRegistrableLabels(unittest.TestCase):
    def test_strips_two_label_suffix(self):
        self.assertEqual(_registrable_labels("a.b.c.example.com"), ["a", "b", "c"])

    def test_two_labels_empty(self):
        self.assertEqual(_registrable_labels("example.com"), [])

    def test_single_label_empty(self):
        self.assertEqual(_registrable_labels("localhost"), [])

    def test_handles_trailing_dots(self):
        self.assertEqual(_registrable_labels("a.b.example.com."), ["a", "b"])


class TestSeverityBands(unittest.TestCase):
    def test_high(self):
        self.assertEqual(_severity_from_score(0.9), "high")
        self.assertEqual(_severity_from_score(0.75), "high")

    def test_medium(self):
        self.assertEqual(_severity_from_score(0.5), "medium")
        self.assertEqual(_severity_from_score(0.74), "medium")

    def test_low(self):
        self.assertEqual(_severity_from_score(0.49), "low")
        self.assertEqual(_severity_from_score(0.0), "low")


class TestParseLog(unittest.TestCase):
    def test_skips_blanks_and_comments(self):
        events = parse_log(["", "# c", '{"ts":1,"src":"a","dst":"b"}'])
        self.assertEqual(len(events), 1)

    def test_non_object_raises(self):
        with self.assertRaises(ValueError):
            parse_log(["[1,2,3]"])

    def test_missing_src_raises(self):
        with self.assertRaises(ValueError):
            parse_log(['{"ts":1,"dst":"b"}'])

    def test_proto_lowercased(self):
        events = parse_log(['{"ts":1,"src":"a","dst":"b","proto":"DNS"}'])
        self.assertEqual(events[0].proto, "dns")

    def test_bytes_coerced(self):
        events = parse_log(['{"ts":1,"src":"a","dst":"b","bytes":"500"}'])
        self.assertEqual(events[0].bytes, 500)

    def test_bytes_null_safe(self):
        events = parse_log(['{"ts":1,"src":"a","dst":"b","bytes":null}'])
        self.assertEqual(events[0].bytes, 0)

    def test_line_number_in_error(self):
        try:
            parse_log(['{"ts":1,"src":"a","dst":"b"}', "{bad}"])
        except ValueError as e:
            self.assertIn("line 2", str(e))
        else:
            self.fail("expected ValueError")


def _dns(src, dst, query, ts=0):
    return LogEvent(ts=ts, src=src, dst=dst, proto="dns", query=query)


class TestDetectEntropy(unittest.TestCase):
    def test_flags_high_entropy_tunnel(self):
        evs = [
            _dns("10.0.0.5", "evil.example.net", "mfrggzdfmztwq2lknbswg43f.x9q2zz.evil.example.net"),
            _dns("10.0.0.5", "evil.example.net", "nbswy3dpfqqho33snrscc4r.zwy7q9.evil.example.net"),
        ]
        f = detect_entropy(evs)
        self.assertTrue(any(x.dst == "evil.example.net" for x in f))

    def test_benign_below_threshold(self):
        evs = [_dns("a", "www.example.com", "www.example.com")]
        self.assertEqual(detect_entropy(evs), [])

    def test_short_labels_ignored(self):
        evs = [_dns("a", "x.y.example.com", "ab.cd.example.com")]
        self.assertEqual(detect_entropy(evs), [])

    def test_http_path_segment(self):
        ev = LogEvent(ts=0, src="a", dst="evil.example.net", proto="http",
                      query="http://evil.example.net/mfrggzdfmztwq2lknbswg43f")
        f = detect_entropy([ev])
        self.assertTrue(any(x.dst == "evil.example.net" for x in f))

    def test_http_host_not_flagged(self):
        ev = LogEvent(ts=0, src="a", dst="updates.example.com", proto="http",
                      query="http://updates.example.com/")
        self.assertEqual(detect_entropy([ev]), [])

    def test_score_in_range(self):
        evs = [_dns("a", "e.x.example.net", "mfrggzdfmztwq2lknbswg43f.aa.e.x.example.net")]
        for f in detect_entropy(evs):
            self.assertGreaterEqual(f.score, 0.0)
            self.assertLessEqual(f.score, 1.0)


class TestDetectBeaconing(unittest.TestCase):
    def _beacon(self, n=10, interval=60.0, jitter=0.0):
        evs = []
        t = 1000.0
        for i in range(n):
            evs.append(LogEvent(ts=t, src="10.0.0.5", dst="c2.example.net", proto="http"))
            t += interval + (jitter if i % 2 else -jitter)
        return evs

    def test_regular_beacon_flagged(self):
        f = detect_beaconing(self._beacon())
        self.assertTrue(any(x.dst == "c2.example.net" for x in f))

    def test_too_few_events_ignored(self):
        self.assertEqual(detect_beaconing(self._beacon(n=3)), [])

    def test_high_jitter_not_flagged(self):
        f = detect_beaconing(self._beacon(interval=60.0, jitter=40.0))
        self.assertEqual(f, [])

    def test_high_count_high_score(self):
        f = detect_beaconing(self._beacon(n=30))
        self.assertTrue(f)
        self.assertGreater(f[0].score, 0.7)

    def test_min_events_param(self):
        evs = self._beacon(n=5)
        self.assertEqual(detect_beaconing(evs, min_events=6), [])


class TestDetectLongDns(unittest.TestCase):
    def test_oversized_name_flagged(self):
        name = ("a" * 40) + ".b" + ("c" * 20) + ".tunnel.example.net"
        f = detect_long_dns([_dns("a", "tunnel.example.net", name)])
        self.assertTrue(f)

    def test_normal_not_flagged(self):
        self.assertEqual(detect_long_dns([_dns("a", "www.example.com", "www.example.com")]), [])

    def test_only_dns_proto(self):
        ev = LogEvent(ts=0, src="a", dst="x", proto="http",
                      query="/" + "z" * 200)
        self.assertEqual(detect_long_dns([ev]), [])

    def test_keeps_worst_per_pair(self):
        short = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.x.tunnel.example.net"
        longer = ("b" * 90) + ".x.tunnel.example.net"
        f = detect_long_dns([_dns("a", "tunnel.example.net", short),
                             _dns("a", "tunnel.example.net", longer)])
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].evidence["name_length"], len(longer))


class TestAnalyze(unittest.TestCase):
    def test_sorted_desc(self):
        evs = [
            _dns("a", "e.x.example.net", "mfrggzdfmztwq2lknbswg43f.aa.e.x.example.net"),
            _dns("a", "tunnel.example.net", ("z" * 90) + ".q.tunnel.example.net"),
        ]
        f = analyze(evs)
        scores = [x.score for x in f]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_empty_events(self):
        self.assertEqual(analyze([]), [])

    def test_threshold_param_affects_results(self):
        evs = [_dns("a", "x.y.example.net", "newsletteritem.aa.x.y.example.net")]
        loose = analyze(evs, entropy_threshold=2.0)
        strict = analyze(evs, entropy_threshold=5.0)
        self.assertGreaterEqual(len(loose), len(strict))


class TestSarif(unittest.TestCase):
    def _findings(self):
        return [
            Finding("entropy", "high", "10.0.0.5", "evil.example.net", 0.9, "hi",
                    evidence={"peak_entropy": 4.2}),
            Finding("beaconing", "medium", "10.0.0.6", "c2.example.net", 0.6, "beacon"),
        ]

    def test_schema_and_version(self):
        s = to_sarif(self._findings())
        self.assertEqual(s["version"], "2.1.0")
        self.assertIn("$schema", s)

    def test_result_count_matches(self):
        s = to_sarif(self._findings())
        self.assertEqual(len(s["runs"][0]["results"]), 2)

    def test_levels_mapped(self):
        s = to_sarif(self._findings())
        levels = {r["level"] for r in s["runs"][0]["results"]}
        self.assertTrue(levels.issubset({"error", "warning", "note"}))

    def test_rules_present(self):
        s = to_sarif(self._findings())
        rules = s["runs"][0]["tool"]["driver"]["rules"]
        self.assertGreaterEqual(len(rules), 3)

    def test_empty_findings(self):
        s = to_sarif([])
        self.assertEqual(s["runs"][0]["results"], [])

    def test_log_uri_recorded(self):
        s = to_sarif(self._findings(), log_uri="my.jsonl")
        loc = s["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        self.assertEqual(loc["artifactLocation"]["uri"], "my.jsonl")


class TestFindingToDict(unittest.TestCase):
    def test_roundtrip_keys(self):
        f = Finding("entropy", "high", "a", "b", 0.9, "s")
        d = f.to_dict()
        for k in ("detector", "severity", "src", "dst", "score", "summary", "evidence"):
            self.assertIn(k, d)


if __name__ == "__main__":
    unittest.main()
