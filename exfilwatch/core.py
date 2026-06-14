"""Core detection engine for EXFILWATCH.

Real logic, standard library only. No network, no external deps.

Input model: newline-delimited JSON log events, each with at least:
    ts      (float|int|ISO-8601 str)  - event timestamp
    src     (str)                     - source/internal host (IP or name)
    dst     (str)                     - destination host / domain
    proto   (str)                     - "dns" or "http" (others ignored for query analysis)
    query   (str, optional)          - dns name queried or http path/url
    bytes   (int, optional)          - bytes transferred (used for volume context)

Detectors:
  * entropy   - high Shannon entropy in DNS labels / HTTP paths (encoded payload)
  * beaconing - regular, low-jitter intervals between a src->dst pair
  * long_dns  - abnormally long DNS query names (tunneling)
"""
from __future__ import annotations

import json
import math
import statistics
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Iterable


@dataclass
class LogEvent:
    ts: float
    src: str
    dst: str
    proto: str = ""
    query: str = ""
    bytes: int = 0
    raw: dict = field(default_factory=dict, repr=False)


@dataclass
class Finding:
    detector: str          # "entropy" | "beaconing" | "long_dns"
    severity: str          # "low" | "medium" | "high"
    src: str
    dst: str
    score: float           # normalized 0..1 confidence-ish score
    summary: str
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def shannon_entropy(s: str) -> float:
    """Shannon entropy (bits/char) of a string. 0 for empty."""
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    ent = 0.0
    for c in counts.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


def _parse_ts(value: Any) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        v = value.strip()
        # epoch as string
        try:
            return float(v)
        except ValueError:
            pass
        # ISO-8601
        try:
            v2 = v.replace("Z", "+00:00")
            return datetime.fromisoformat(v2).timestamp()
        except ValueError:
            pass
    raise ValueError(f"unparseable timestamp: {value!r}")


def parse_log(lines: Iterable[str]) -> list[LogEvent]:
    """Parse newline-delimited JSON log lines into LogEvent objects.

    Blank lines and lines starting with '#' are skipped. Malformed lines
    raise ValueError with the line number for actionable triage.
    """
    events: list[LogEvent] = []
    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        try:
            obj = json.loads(stripped)
        except json.JSONDecodeError as e:
            raise ValueError(f"line {i}: invalid JSON: {e}") from e
        if not isinstance(obj, dict):
            raise ValueError(f"line {i}: expected JSON object, got {type(obj).__name__}")
        try:
            ts = _parse_ts(obj["ts"])
            src = str(obj["src"])
            dst = str(obj["dst"])
        except KeyError as e:
            raise ValueError(f"line {i}: missing required field {e}") from e
        except ValueError as e:
            raise ValueError(f"line {i}: {e}") from e
        raw_bytes = obj.get("bytes", 0) or 0
        try:
            parsed_bytes = int(raw_bytes)
        except (TypeError, ValueError):
            raise ValueError(
                f"line {i}: 'bytes' must be an integer, got {raw_bytes!r}"
            )
        events.append(
            LogEvent(
                ts=ts,
                src=src,
                dst=dst,
                proto=str(obj.get("proto", "")).lower(),
                query=str(obj.get("query", "")),
                bytes=parsed_bytes,
                raw=obj,
            )
        )
    return events


def _registrable_labels(domain: str) -> list[str]:
    """Return DNS labels excluding the (assumed 2-label) registrable suffix.

    e.g. 'a8f3.x9q2.evil.example.com' -> ['a8f3', 'x9q2', 'evil'].
    Heuristic, suffix-list-free: keep all but the last two labels.
    """
    parts = [p for p in domain.split(".") if p]
    if len(parts) <= 2:
        return []
    return parts[:-2]


def _severity_from_score(score: float) -> str:
    if score >= 0.75:
        return "high"
    if score >= 0.5:
        return "medium"
    return "low"


def detect_entropy(
    events: list[LogEvent],
    entropy_threshold: float = 3.5,
    min_len: int = 8,
) -> list[Finding]:
    """Flag DNS labels / HTTP paths with high Shannon entropy (encoded payload).

    Aggregates per src->dst so a single tunnel produces one finding, scored by
    the fraction of high-entropy queries and the peak entropy observed.
    """
    # group candidate strings per (src, dst)
    groups: dict[tuple[str, str], list[tuple[str, float]]] = {}
    for ev in events:
        candidates: list[str] = []
        if ev.proto == "dns":
            candidates = _registrable_labels(ev.query or ev.dst)
        elif ev.proto == "http":
            path = ev.query
            if "://" in path:
                path = path.split("://", 1)[1]
            # take path/query segments
            for seg in path.replace("?", "/").replace("&", "/").split("/"):
                if seg:
                    candidates.append(seg)
        for cand in candidates:
            if len(cand) < min_len:
                continue
            groups.setdefault((ev.src, ev.dst), []).append((cand, shannon_entropy(cand)))

    findings: list[Finding] = []
    for (src, dst), items in groups.items():
        high = [(c, e) for c, e in items if e >= entropy_threshold]
        if not high:
            continue
        frac = len(high) / len(items)
        peak = max(e for _, e in high)
        # score: blend fraction of suspicious labels and how far peak exceeds threshold
        peak_factor = min(1.0, (peak - entropy_threshold) / 1.5)
        score = round(min(1.0, 0.5 * frac + 0.5 * peak_factor), 3)
        worst = max(high, key=lambda t: t[1])
        findings.append(
            Finding(
                detector="entropy",
                severity=_severity_from_score(score),
                src=src,
                dst=dst,
                score=score,
                summary=(
                    f"{len(high)}/{len(items)} labels exceed entropy {entropy_threshold} "
                    f"(peak {peak:.2f} bits/char) toward {dst}"
                ),
                evidence={
                    "high_entropy_count": len(high),
                    "sample_count": len(items),
                    "peak_entropy": round(peak, 3),
                    "worst_label": worst[0][:64],
                    "worst_label_entropy": round(worst[1], 3),
                },
            )
        )
    return findings


def detect_beaconing(
    events: list[LogEvent],
    min_events: int = 4,
    max_jitter_ratio: float = 0.15,
) -> list[Finding]:
    if min_events < 2:
        raise ValueError("beacon min_events must be >= 2")
    if max_jitter_ratio <= 0:
        raise ValueError("beacon max_jitter_ratio must be > 0")
    """Detect periodic callbacks (beaconing) per src->dst pair.

    A beacon shows tightly clustered inter-arrival intervals. We measure the
    coefficient of variation (stdev/mean) of intervals; low CV => regular beacon.
    """
    pairs: dict[tuple[str, str], list[float]] = {}
    for ev in events:
        pairs.setdefault((ev.src, ev.dst), []).append(ev.ts)

    findings: list[Finding] = []
    for (src, dst), tss in pairs.items():
        if len(tss) < min_events:
            continue
        tss = sorted(tss)
        intervals = [b - a for a, b in zip(tss, tss[1:]) if b - a > 0]
        if len(intervals) < min_events - 1:
            continue
        mean = statistics.fmean(intervals)
        if mean <= 0:
            continue
        stdev = statistics.pstdev(intervals)
        cv = stdev / mean  # coefficient of variation (jitter ratio)
        if cv > max_jitter_ratio:
            continue
        # lower CV and more events => higher score
        regularity = max(0.0, 1.0 - (cv / max_jitter_ratio))
        count_factor = min(1.0, len(intervals) / 20.0)
        score = round(min(1.0, 0.7 * regularity + 0.3 * count_factor), 3)
        findings.append(
            Finding(
                detector="beaconing",
                severity=_severity_from_score(score),
                src=src,
                dst=dst,
                score=score,
                summary=(
                    f"regular beacon every ~{mean:.1f}s (jitter {cv*100:.1f}%) "
                    f"over {len(tss)} callbacks to {dst}"
                ),
                evidence={
                    "event_count": len(tss),
                    "mean_interval_s": round(mean, 3),
                    "interval_cv": round(cv, 4),
                    "jitter_pct": round(cv * 100, 2),
                },
            )
        )
    return findings


def detect_long_dns(
    events: list[LogEvent],
    max_name_len: int = 52,
    max_label_len: int = 30,
) -> list[Finding]:
    """Flag abnormally long DNS query names / labels (payload smuggling)."""
    worst: dict[tuple[str, str], tuple[int, int, str]] = {}
    for ev in events:
        if ev.proto != "dns":
            continue
        name = ev.query or ev.dst
        if not name:
            continue
        labels = _registrable_labels(name)
        longest_label = max((len(lbl) for lbl in labels), default=0)
        if len(name) <= max_name_len and longest_label <= max_label_len:
            continue
        key = (ev.src, ev.dst)
        prev = worst.get(key)
        if prev is None or len(name) > prev[0]:
            worst[key] = (len(name), longest_label, name)

    findings: list[Finding] = []
    for (src, dst), (name_len, label_len, name) in worst.items():
        len_over = max(0, name_len - max_name_len) / max_name_len
        label_over = max(0, label_len - max_label_len) / max_label_len
        score = round(min(1.0, 0.4 + 0.6 * min(1.0, max(len_over, label_over))), 3)
        findings.append(
            Finding(
                detector="long_dns",
                severity=_severity_from_score(score),
                src=src,
                dst=dst,
                score=score,
                summary=(
                    f"oversized DNS query ({name_len} chars, longest label {label_len}) to {dst}"
                ),
                evidence={
                    "name_length": name_len,
                    "longest_label": label_len,
                    "sample": name[:96],
                },
            )
        )
    return findings


def analyze(
    events: list[LogEvent],
    entropy_threshold: float = 3.5,
    beacon_min_events: int = 4,
    beacon_max_jitter: float = 0.15,
    dns_max_len: int = 52,
) -> list[Finding]:
    """Run all detectors and return findings sorted high-severity first."""
    findings: list[Finding] = []
    findings += detect_entropy(events, entropy_threshold=entropy_threshold)
    findings += detect_beaconing(
        events, min_events=beacon_min_events, max_jitter_ratio=beacon_max_jitter
    )
    findings += detect_long_dns(events, max_name_len=dns_max_len)
    findings.sort(key=lambda f: f.score, reverse=True)
    return findings
