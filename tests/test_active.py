"""Tests for the authorization-gated ACTIVE mode. localhost / mocks only."""
import os
import sys
import socket
import threading
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from exfilwatch import active
from exfilwatch.active import (
    ProbeResult,
    in_scope,
    probe_targets,
    targets_from_findings,
    _parse_target,
)
from exfilwatch.core import Finding


class TestParseTarget(unittest.TestCase):
    def test_host_port(self):
        self.assertEqual(_parse_target("host.example.com:8443"), ("host.example.com", 8443))

    def test_host_default_port(self):
        self.assertEqual(_parse_target("host.example.com"), ("host.example.com", 443))

    def test_ipv6_bracketed(self):
        self.assertEqual(_parse_target("[::1]:8080"), ("::1", 8080))

    def test_empty_raises(self):
        with self.assertRaises(ValueError):
            _parse_target("   ")


class TestScope(unittest.TestCase):
    def test_empty_allowlist_matches_nothing(self):
        self.assertFalse(in_scope("anything.com", []))

    def test_exact_host(self):
        self.assertTrue(in_scope("evil.example.net", ["evil.example.net"]))
        self.assertFalse(in_scope("other.example.net", ["evil.example.net"]))

    def test_host_case_and_trailing_dot(self):
        self.assertTrue(in_scope("Evil.Example.Net.", ["evil.example.net"]))

    def test_exact_ip(self):
        self.assertTrue(in_scope("10.0.0.5", ["10.0.0.5"]))
        self.assertFalse(in_scope("10.0.0.6", ["10.0.0.5"]))

    def test_cidr(self):
        self.assertTrue(in_scope("10.0.0.250", ["10.0.0.0/24"]))
        self.assertFalse(in_scope("10.0.1.5", ["10.0.0.0/24"]))

    def test_cidr_does_not_match_hostname(self):
        self.assertFalse(in_scope("host.example.com", ["10.0.0.0/24"]))

    def test_empty_entries_ignored(self):
        self.assertFalse(in_scope("x.com", ["", "  "]))


class TestProbeGates(unittest.TestCase):
    def test_refuses_without_authorization(self):
        res = probe_targets(["host:443"], authorized=False, allowlist=["host"])
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0].state, "refused")

    def test_refuses_with_empty_allowlist(self):
        res = probe_targets(["host:443"], authorized=True, allowlist=[])
        self.assertEqual(res[0].state, "refused")

    def test_refuses_with_whitespace_allowlist(self):
        res = probe_targets(["host:443"], authorized=True, allowlist=["", "  "])
        self.assertEqual(res[0].state, "refused")

    def test_out_of_scope_skipped_not_probed(self):
        called = []

        def fake_connect(host, port, timeout, banner):
            called.append((host, port))
            return ProbeResult(host=host, port=port, state="open")

        res = probe_targets(
            ["in.example.com:443", "out.example.com:443"],
            authorized=True,
            allowlist=["in.example.com"],
            _connect=fake_connect,
            _sleep=lambda s: None,
        )
        states = {r.host: r.state for r in res}
        self.assertEqual(states["in.example.com"], "open")
        self.assertEqual(states["out.example.com"], "skipped")
        self.assertEqual(called, [("in.example.com", 443)])

    def test_rate_limit_spacing_invoked(self):
        sleeps = []
        res = probe_targets(
            ["a.example.com:443", "a.example.com:444"],
            authorized=True,
            allowlist=["a.example.com"],
            rate_limit=2.0,
            _connect=lambda h, p, t, b: ProbeResult(host=h, port=p, state="open"),
            _sleep=lambda s: sleeps.append(s),
        )
        # one sleep between the two in-scope probes; ~0.5s for 2 pps
        self.assertEqual(len(sleeps), 1)
        self.assertAlmostEqual(sleeps[0], 0.5, places=3)

    def test_bad_target_recorded_as_error(self):
        res = probe_targets(
            [12345],
            authorized=True,
            allowlist=["x"],
            _connect=lambda h, p, t, b: ProbeResult(host=h, port=p, state="open"),
            _sleep=lambda s: None,
        )
        # 12345 -> host "12345" not in scope -> skipped (parsed fine)
        self.assertIn(res[0].state, ("skipped", "error"))


class TestProbeLocalhost(unittest.TestCase):
    """Real TCP connect, but ONLY to a localhost fixture server."""

    @classmethod
    def setUpClass(cls):
        cls.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cls.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        cls.srv.bind(("127.0.0.1", 0))
        cls.srv.listen(5)
        cls.port = cls.srv.getsockname()[1]
        cls._stop = False

        def serve():
            while not cls._stop:
                try:
                    cls.srv.settimeout(0.3)
                    conn, _ = cls.srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                try:
                    conn.sendall(b"EXFIL-FIXTURE-BANNER\r\n")
                except OSError:
                    pass
                finally:
                    conn.close()

        cls.t = threading.Thread(target=serve, daemon=True)
        cls.t.start()

    @classmethod
    def tearDownClass(cls):
        cls._stop = True
        try:
            cls.srv.close()
        except OSError:
            pass

    def test_open_port_detected(self):
        res = probe_targets(
            [f"127.0.0.1:{self.port}"],
            authorized=True,
            allowlist=["127.0.0.1"],
            rate_limit=100.0,
        )
        self.assertEqual(res[0].state, "open")
        self.assertIsNotNone(res[0].rtt_ms)

    def test_banner_grab_optional(self):
        res = probe_targets(
            [f"127.0.0.1:{self.port}"],
            authorized=True,
            allowlist=["127.0.0.1"],
            rate_limit=100.0,
            grab_banner=True,
        )
        self.assertIn("FIXTURE", res[0].banner)

    def test_closed_port(self):
        # find a port nothing listens on
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        free = s.getsockname()[1]
        s.close()
        res = probe_targets(
            [f"127.0.0.1:{free}"],
            authorized=True,
            allowlist=["127.0.0.1"],
            rate_limit=100.0,
            timeout=1.0,
        )
        self.assertIn(res[0].state, ("closed", "filtered", "error"))


class TestTargetsFromFindings(unittest.TestCase):
    def _f(self, dst):
        return Finding(detector="beaconing", severity="high", src="10.0.0.1",
                       dst=dst, score=0.9, summary="x")

    def test_domain_gets_default_port(self):
        t = targets_from_findings([self._f("evil.example.net")])
        self.assertEqual(t, ["evil.example.net:443"])

    def test_dedup(self):
        t = targets_from_findings([self._f("a.com"), self._f("a.com")])
        self.assertEqual(t, ["a.com:443"])

    def test_host_with_port_preserved(self):
        t = targets_from_findings([self._f("c2.example.net:8443")])
        self.assertEqual(t, ["c2.example.net:8443"])

    def test_empty_dst_dropped(self):
        self.assertEqual(targets_from_findings([self._f("")]), [])


if __name__ == "__main__":
    unittest.main()
