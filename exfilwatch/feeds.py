"""feeds — threat-intel enrichment for EXFILWATCH (edge / air-gap deployable).

EXFILWATCH detects DNS/HTTP exfiltration *behaviour* (entropy, beaconing,
oversized DNS) with zero external data. This module adds **attribution**: it
cross-references the destination IPs and domains in a scan against two real,
keyless abuse.ch feeds and tells you *which known C2 / malware family* a
destination belongs to.

Consumed catalog feeds (defensive / authorized-use intelligence only):

  * ``feodo-c2``  — abuse.ch Feodo Tracker botnet C2 IP blocklist
                    https://feodotracker.abuse.ch/downloads/ipblocklist.json
  * ``threatfox`` — abuse.ch ThreatFox recent IOCs (IP/domain/url/hash)
                    https://threatfox.abuse.ch/export/json/recent/

The feeds are fetched, cached to disk and re-served **offline** by the bundled
``datafeeds`` module, so this works on disconnected / edge gear. Set
``COGNIS_FEEDS_CACHE`` to a directory that holds a snapshot and pass
``offline=True`` to never touch the network.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field, asdict
from typing import Any, Iterable, Optional

# Only these catalog feed ids are relevant to exfilwatch (threat-intel domain).
FEED_IDS = ("feodo-c2", "threatfox")

try:  # bundled alongside this package (datafeeds.py + data_feeds_2026.json)
    from . import datafeeds as _df  # type: ignore
except Exception:  # pragma: no cover - fallback when imported flat
    import datafeeds as _df  # type: ignore


# --------------------------------------------------------------------------- #
# indicator model
# --------------------------------------------------------------------------- #
@dataclass
class IntelHit:
    """One feed match against a scanned destination."""
    indicator: str          # the dst IP / domain that matched
    indicator_type: str     # "ip" | "domain"
    feed: str               # "feodo-c2" | "threatfox"
    malware: str            # malware family / threat label
    confidence: int         # 0..100
    status: str = ""        # feed-specific (e.g. feodo "online"/"offline")
    detail: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------------- #
# feed -> normalized indicator index
# --------------------------------------------------------------------------- #
def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def build_index(*, offline: bool = False, feed_ids: Iterable[str] = FEED_IDS,
                max_age_hours: float = 6.0) -> dict[str, list[IntelHit]]:
    """Build an indicator -> [IntelHit] lookup from the consumed feeds.

    ``offline=True`` serves only the on-disk cache (raises if a feed is not
    cached). Online, feeds older than ``max_age_hours`` are refreshed.
    """
    index: dict[str, list[IntelHit]] = {}

    for fid in feed_ids:
        if fid not in FEED_IDS:
            raise ValueError(f"feed {fid!r} is not relevant to exfilwatch; "
                             f"allowed: {', '.join(FEED_IDS)}")
        data = _df.get(fid, offline=offline, max_age_hours=max_age_hours)

        if fid == "feodo-c2":
            # list[ {ip_address, port, status, malware, as_name, country, ...} ]
            for row in data or []:
                ip = str(row.get("ip_address", "")).strip()
                if not ip:
                    continue
                index.setdefault(ip, []).append(IntelHit(
                    indicator=ip,
                    indicator_type="ip",
                    feed=fid,
                    malware=row.get("malware") or "unknown",
                    confidence=100,  # Feodo lists confirmed C2 only
                    status=row.get("status", ""),
                    detail={k: row.get(k) for k in
                            ("port", "as_number", "as_name", "country",
                             "first_seen", "last_online") if row.get(k) is not None},
                ))

        elif fid == "threatfox":
            # dict[id] -> list[ {ioc_value, ioc_type, malware_printable, confidence_level, ...} ]
            rows: list[dict[str, Any]] = []
            if isinstance(data, dict):
                for v in data.values():
                    rows.extend(v if isinstance(v, list) else [v])
            elif isinstance(data, list):
                rows = data
            for row in rows:
                if not isinstance(row, dict):
                    continue
                ioc = str(row.get("ioc_value", "")).strip()
                if not ioc:
                    continue
                itype = row.get("ioc_type", "")
                if itype.startswith("ip"):  # ip:port -> ip
                    ind = ioc.split(":", 1)[0]
                    ind_type = "ip"
                elif itype in ("domain", "hostname"):
                    ind = ioc.lower()
                    ind_type = "domain"
                else:
                    continue  # url/hash IOCs don't map onto dst host matching
                index.setdefault(ind, []).append(IntelHit(
                    indicator=ind,
                    indicator_type=ind_type,
                    feed=fid,
                    malware=row.get("malware_printable") or row.get("malware") or "unknown",
                    confidence=int(row.get("confidence_level") or 0),
                    status=row.get("threat_type", ""),
                    detail={k: row.get(k) for k in
                            ("first_seen_utc", "last_seen_utc", "tags",
                             "is_compromised") if row.get(k) is not None},
                ))

    return index


# --------------------------------------------------------------------------- #
# match scanned destinations against the index
# --------------------------------------------------------------------------- #
def _dst_candidates(dst: str) -> list[tuple[str, str]]:
    """Return (indicator, type) candidates for a finding's dst.

    A dst may be an IP, a host:port, or a domain (with optional trailing dot).
    """
    dst = (dst or "").strip().rstrip(".")
    if not dst:
        return []
    host = dst.split(":", 1)[0] if dst.count(":") == 1 and not _is_ip(dst) else dst
    out: list[tuple[str, str]] = []
    if _is_ip(host):
        out.append((host, "ip"))
    else:
        out.append((host.lower(), "domain"))
    return out


def enrich(findings: list, *, offline: bool = False,
           index: Optional[dict[str, list[IntelHit]]] = None,
           max_age_hours: float = 6.0) -> dict[str, list[IntelHit]]:
    """Cross-reference each finding's ``dst`` against the threat-intel index.

    Returns a map of ``dst`` -> matched ``IntelHit`` list, and attaches the same
    hits onto each Finding's ``evidence['intel']`` so JSON/SARIF output carries
    attribution. Findings whose dst matches a confirmed C2 get bumped to high.
    """
    if index is None:
        index = build_index(offline=offline, max_age_hours=max_age_hours)

    matches: dict[str, list[IntelHit]] = {}
    for f in findings:
        hits: list[IntelHit] = []
        for ind, _t in _dst_candidates(getattr(f, "dst", "")):
            hits.extend(index.get(ind, []))
        if not hits:
            continue
        matches[f.dst] = hits
        # attach attribution to the finding's evidence (best/highest first)
        hits.sort(key=lambda h: h.confidence, reverse=True)
        try:
            ev = getattr(f, "evidence", None)
            if isinstance(ev, dict):
                ev["intel"] = [h.to_dict() for h in hits]
                ev["intel_malware"] = sorted({h.malware for h in hits})
            # a confirmed-C2 destination is unambiguously high severity
            top = hits[0]
            if top.confidence >= 75:
                f.severity = "high"
                f.score = max(getattr(f, "score", 0.0), 0.99)
                f.summary = (f"{f.summary} | KNOWN C2: {top.malware} "
                             f"({top.feed})")
        except Exception:  # pragma: no cover - never let enrichment break a scan
            pass
    return matches


def index_stats(index: dict[str, list[IntelHit]]) -> dict[str, int]:
    """Quick counts for CLI/demo output."""
    ips = sum(1 for v in index.values() for h in v if h.indicator_type == "ip")
    domains = sum(1 for v in index.values() for h in v if h.indicator_type == "domain")
    return {"indicators": len(index), "ip_hits": ips, "domain_hits": domains}
