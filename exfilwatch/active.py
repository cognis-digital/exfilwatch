"""active — AUTHORIZED-USE-ONLY active reachability probing for EXFILWATCH.

EXFILWATCH is a DEFENSIVE tool. Its primary mode is **passive**: it analyses
logs you already have, entirely offline, and never touches the network.

This module adds an **optional, off-by-default ACTIVE mode**. Given a set of
suspicious destinations (from a passive scan, or supplied directly), it makes a
*single, minimal TCP connect* to confirm whether a flagged beacon/exfil target
is actually reachable and listening — useful for incident responders triaging a
detection on infrastructure **they are authorized to assess**.

It does NOT send any payload. It opens a socket, observes connect/refused/
timeout, optionally peeks at a TLS/HTTP banner offered by the peer, and closes.
There are no exploits, no fuzzing, no data exfiltration — only a connectivity
check a defender could perform with ``nc -z``.

HARD SAFETY GATES (all required for any active probe to run):
  1. ``authorized=True``  — the caller asserts written authorization.
  2. A non-empty ``allowlist`` (scope). Every target host MUST match an entry
     (exact host, or CIDR for IPs). Out-of-scope targets are SKIPPED, never
     probed.
  3. ``rate_limit`` (probes/second) is enforced between probes.
Defaults are chosen so that *doing nothing* is the safe path: with no
authorization or empty allowlist, :func:`probe_targets` refuses and returns an
empty result with a ``refused`` reason.

Tests exercise this against localhost / a bundled fixture server / mocks ONLY —
never a real external host.
"""
from __future__ import annotations

import ipaddress
import socket
import time
from dataclasses import dataclass, field, asdict
from typing import Iterable, Optional

BANNER = (
    "=" * 70 + "\n"
    "  EXFILWATCH ACTIVE MODE  --  AUTHORIZED USE ONLY\n"
    "  You are about to make live network connections to the targets below.\n"
    "  Only proceed against infrastructure you OWN or have WRITTEN permission\n"
    "  to assess. Active probing of third-party systems may be illegal.\n"
    + "=" * 70
)


@dataclass
class ProbeResult:
    host: str
    port: int
    state: str             # "open" | "closed" | "filtered" | "skipped" | "error"
    rtt_ms: Optional[float] = None
    banner: str = ""
    reason: str = ""
    detail: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


class ScopeError(PermissionError):
    """Raised when an active probe is attempted outside the authorized gates."""


# --------------------------------------------------------------------------- #
# scope enforcement
# --------------------------------------------------------------------------- #
def _parse_target(target: str) -> tuple[str, int]:
    """Parse 'host:port' (or 'host' -> default 443). IPv6 must be bracketed."""
    t = target.strip()
    if not t:
        raise ValueError("empty target")
    if t.startswith("["):  # [ipv6]:port
        host, _, rest = t[1:].partition("]")
        port = int(rest.lstrip(":")) if rest.lstrip(":") else 443
        return host, port
    if t.count(":") == 1:
        host, _, p = t.partition(":")
        return host, int(p) if p else 443
    return t, 443


def in_scope(host: str, allowlist: Iterable[str]) -> bool:
    """True if ``host`` matches an allowlist entry.

    Entries may be: an exact hostname (case-insensitive, trailing dot ignored),
    an exact IP, or a CIDR network (IPs only). An empty allowlist matches
    nothing — scope must be explicit.
    """
    h = (host or "").strip().rstrip(".").lower()
    if not h:
        return False
    host_ip: Optional[ipaddress._BaseAddress] = None
    try:
        host_ip = ipaddress.ip_address(h)
    except ValueError:
        host_ip = None

    for entry in allowlist:
        e = (entry or "").strip().rstrip(".").lower()
        if not e:
            continue
        if host_ip is not None and ("/" in e or _looks_like_ip(e)):
            try:
                if host_ip in ipaddress.ip_network(e, strict=False):
                    return True
            except ValueError:
                pass
        if e == h:
            return True
    return False


def _looks_like_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s.split("/", 1)[0])
        return True
    except ValueError:
        return False


# --------------------------------------------------------------------------- #
# the probe
# --------------------------------------------------------------------------- #
def _connect_probe(host: str, port: int, timeout: float, grab_banner: bool) -> ProbeResult:
    """Single TCP connect. No payload sent unless a passive banner is offered."""
    start = time.monotonic()
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        rtt = (time.monotonic() - start) * 1000.0
        banner = ""
        if grab_banner:
            try:
                sock.settimeout(min(timeout, 1.5))
                data = sock.recv(128)  # read only what the peer volunteers
                banner = data.decode("latin-1", "replace").strip()
            except (socket.timeout, OSError):
                banner = ""
        return ProbeResult(host=host, port=port, state="open",
                           rtt_ms=round(rtt, 2), banner=banner[:128])
    except socket.timeout:
        return ProbeResult(host=host, port=port, state="filtered",
                           reason="connect timed out")
    except ConnectionRefusedError:
        rtt = (time.monotonic() - start) * 1000.0
        return ProbeResult(host=host, port=port, state="closed",
                           rtt_ms=round(rtt, 2), reason="connection refused")
    except (socket.gaierror, OSError) as e:
        return ProbeResult(host=host, port=port, state="error", reason=str(e))
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def probe_targets(
    targets: Iterable[str],
    *,
    authorized: bool = False,
    allowlist: Optional[Iterable[str]] = None,
    rate_limit: float = 1.0,
    timeout: float = 3.0,
    grab_banner: bool = False,
    _connect=_connect_probe,
    _sleep=time.sleep,
) -> list[ProbeResult]:
    """Probe ``targets`` ('host[:port]') — ONLY when fully authorized & in scope.

    Refuses (returns a single ``refused`` ProbeResult) unless ``authorized`` is
    True AND ``allowlist`` is non-empty. Each in-scope target gets one TCP
    connect; out-of-scope targets are returned as ``state='skipped'`` and never
    contacted. Probes are spaced by ``1/rate_limit`` seconds.

    ``_connect`` / ``_sleep`` are injectable for tests (localhost / mocks only).
    """
    allow = [a for a in (allowlist or []) if str(a).strip()]
    if not authorized or not allow:
        return [ProbeResult(
            host="", port=0, state="refused",
            reason=("active mode requires authorized=True and a non-empty "
                    "allowlist (scope); refusing to probe"),
        )]
    rate_limit = max(rate_limit, 0.001)
    delay = 1.0 / rate_limit

    results: list[ProbeResult] = []
    first = True
    for raw in targets:
        try:
            host, port = _parse_target(str(raw))
        except (ValueError, TypeError) as e:
            results.append(ProbeResult(host=str(raw), port=0, state="error",
                                       reason=f"bad target: {e}"))
            continue
        if not in_scope(host, allow):
            results.append(ProbeResult(host=host, port=port, state="skipped",
                                       reason="out of allowlist scope"))
            continue
        if not first:
            _sleep(delay)
        first = False
        results.append(_connect(host, port, timeout, grab_banner))
    return results


def targets_from_findings(findings: Iterable, default_port: int = 443) -> list[str]:
    """Derive probe targets from passive findings' ``dst`` values (host[:port])."""
    seen: list[str] = []
    for f in findings:
        dst = (getattr(f, "dst", "") or "").strip().rstrip(".")
        if not dst:
            continue
        if dst.count(":") == 1 and not _looks_like_ip(dst):
            cand = dst
        elif _looks_like_ip(dst):
            cand = f"{dst}:{default_port}"
        else:
            cand = f"{dst}:{default_port}"
        if cand not in seen:
            seen.append(cand)
    return seen
