"""Hardening tests: edge-cases, bad input, and out-of-range CLI arguments.

All tests must be stdlib-only and leave the filesystem clean.
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from exfilwatch import cli, parse_log
from exfilwatch.core import detect_beaconing


# ---------------------------------------------------------------------------
# parse_log edge-cases
# ---------------------------------------------------------------------------

class TestParseLogHardening(unittest.TestCase):
    def test_empty_input_returns_empty_list(self):
        """Feeding no lines must succeed and return an empty list."""
        self.assertEqual(parse_log([]), [])

    def test_all_comments_and_blanks_returns_empty(self):
        lines = ["# header", "  ", "\t", "# another comment"]
        self.assertEqual(parse_log(lines), [])

    def test_bytes_non_integer_raises_clear_error(self):
        """Non-numeric 'bytes' value must raise ValueError with line info."""
        line = '{"ts": 1, "src": "a", "dst": "b", "bytes": "1.5k"}'
        with self.assertRaises(ValueError) as ctx:
            parse_log([line])
        self.assertIn("bytes", str(ctx.exception))
        self.assertIn("line 1", str(ctx.exception))

    def test_bytes_null_treated_as_zero(self):
        """JSON null for 'bytes' must be coerced to 0 without error."""
        line = '{"ts": 1, "src": "a", "dst": "b", "bytes": null}'
        events = parse_log([line])
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].bytes, 0)

    def test_ts_unparseable_raises_with_line_number(self):
        """An unparseable timestamp must raise ValueError that names the line."""
        line = '{"ts": {"nested": "object"}, "src": "a", "dst": "b"}'
        with self.assertRaises(ValueError) as ctx:
            parse_log([line])
        self.assertIn("line 1", str(ctx.exception))

    def test_non_dict_json_raises(self):
        """A JSON array at top level must raise ValueError."""
        with self.assertRaises(ValueError):
            parse_log(['[1, 2, 3]'])


# ---------------------------------------------------------------------------
# detect_beaconing guard-rail
# ---------------------------------------------------------------------------

class TestBeaconingGuardrails(unittest.TestCase):
    def test_min_events_less_than_2_raises(self):
        with self.assertRaises(ValueError):
            detect_beaconing([], min_events=1)

    def test_zero_max_jitter_raises(self):
        with self.assertRaises(ValueError):
            detect_beaconing([], max_jitter_ratio=0.0)

    def test_negative_max_jitter_raises(self):
        with self.assertRaises(ValueError):
            detect_beaconing([], max_jitter_ratio=-0.1)

    def test_empty_events_returns_empty(self):
        """No events -> no beaconing findings (no crash)."""
        self.assertEqual(detect_beaconing([]), [])


# ---------------------------------------------------------------------------
# CLI numeric-argument validation (no file I/O needed)
# ---------------------------------------------------------------------------

class TestCliArgValidation(unittest.TestCase):
    def _scan(self, extra_args: list[str]) -> int:
        """Run cli.main with the demo file path plus extra_args."""
        demo = os.path.join(
            os.path.dirname(__file__), "..", "demos", "01-basic", "events.jsonl"
        )
        return cli.main(["scan", demo] + extra_args)

    def test_negative_entropy_threshold_is_error(self):
        rc = self._scan(["--entropy-threshold", "-1.0"])
        self.assertEqual(rc, cli.EXIT_ERROR)

    def test_zero_entropy_threshold_is_error(self):
        rc = self._scan(["--entropy-threshold", "0"])
        self.assertEqual(rc, cli.EXIT_ERROR)

    def test_beacon_min_events_one_is_error(self):
        rc = self._scan(["--beacon-min-events", "1"])
        self.assertEqual(rc, cli.EXIT_ERROR)

    def test_zero_beacon_max_jitter_is_error(self):
        rc = self._scan(["--beacon-max-jitter", "0"])
        self.assertEqual(rc, cli.EXIT_ERROR)

    def test_zero_dns_max_len_is_error(self):
        rc = self._scan(["--dns-max-len", "0"])
        self.assertEqual(rc, cli.EXIT_ERROR)


# ---------------------------------------------------------------------------
# CLI: malformed JSONL produces clean error, not a traceback
# ---------------------------------------------------------------------------

class TestCliMalformedInput(unittest.TestCase):
    def _write_temp(self, content: str) -> str:
        tf = tempfile.NamedTemporaryFile(
            "w", suffix=".jsonl", delete=False, encoding="utf-8"
        )
        tf.write(content)
        tf.close()
        return tf.name

    def test_malformed_json_returns_error_code(self):
        path = self._write_temp("{not valid json}\n")
        try:
            rc = cli.main(["scan", path])
        finally:
            os.unlink(path)
        self.assertEqual(rc, cli.EXIT_ERROR)

    def test_missing_required_field_returns_error_code(self):
        path = self._write_temp('{"ts": 1, "src": "a"}\n')  # no 'dst'
        try:
            rc = cli.main(["scan", path])
        finally:
            os.unlink(path)
        self.assertEqual(rc, cli.EXIT_ERROR)

    def test_empty_file_is_clean_exit(self):
        """An empty log file has no events and no findings -> exit 0."""
        path = self._write_temp("")
        try:
            rc = cli.main(["scan", path])
        finally:
            os.unlink(path)
        self.assertEqual(rc, cli.EXIT_OK)


if __name__ == "__main__":
    unittest.main()
