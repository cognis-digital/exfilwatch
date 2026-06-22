"""CLI-level tests for active-mode gating and passive default. No real hosts."""
import io
import os
import sys
import json
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from exfilwatch import cli
from exfilwatch import active as _active

DEMO = os.path.join(os.path.dirname(__file__), "..", "demos", "01-basic", "events.jsonl")


def _capture(argv):
    out, err = io.StringIO(), io.StringIO()
    o, e = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = out, err
    try:
        rc = cli.main(argv)
    finally:
        sys.stdout, sys.stderr = o, e
    return rc, out.getvalue(), err.getvalue()


class TestActiveGating(unittest.TestCase):
    def test_active_without_authorized_errors(self):
        rc, _out, err = _capture(["scan", DEMO, "--active"])
        self.assertEqual(rc, cli.EXIT_ERROR)
        self.assertIn("authorized", err.lower())

    def test_active_authorized_without_scope_errors(self):
        rc, _out, err = _capture(["scan", DEMO, "--active", "--authorized"])
        self.assertEqual(rc, cli.EXIT_ERROR)
        self.assertIn("allowlist", err.lower())

    def test_active_prints_banner(self):
        # scope that matches nothing real -> all skipped, but banner shows
        rc, _out, err = _capture([
            "scan", DEMO, "--active", "--authorized",
            "--target-allowlist", "192.0.2.0/24",  # TEST-NET, never routed
        ])
        self.assertIn("AUTHORIZED USE ONLY", err)
        self.assertIn("scope:", err)

    def test_passive_is_default_no_probes_key(self):
        rc, out, _err = _capture(["scan", DEMO, "--format", "json"])
        payload = json.loads(out)
        self.assertEqual(payload["mode"], "passive")
        self.assertNotIn("active_probes", payload)

    def test_active_json_mode_field_and_skipped(self):
        # allowlist a doc-only TEST-NET so nothing real is contacted; the demo
        # destinations are domains/RFC1918 and won't match -> all skipped.
        rc, out, _err = _capture([
            "scan", DEMO, "--format", "json", "--active", "--authorized",
            "--target-allowlist", "192.0.2.0/24",
        ])
        payload = json.loads(out)
        self.assertEqual(payload["mode"], "active")
        self.assertIn("active_probes", payload)
        for p in payload["active_probes"]:
            self.assertEqual(p["state"], "skipped")


class TestPassiveOffline(unittest.TestCase):
    def test_clean_log_no_probes_and_ok(self):
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False, encoding="utf-8") as tf:
            tf.write('{"ts": 1, "src": "10.0.0.1", "dst": "www.example.com", "proto": "dns", "query": "www.example.com"}\n')
            path = tf.name
        try:
            rc, out, _err = _capture(["scan", path, "--format", "json"])
            self.assertEqual(rc, cli.EXIT_OK)
            self.assertEqual(json.loads(out)["mode"], "passive")
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
