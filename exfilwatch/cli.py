"""Command-line interface for EXFILWATCH.

Usage:
    python -m exfilwatch scan <logfile>            # analyze a JSONL log
    python -m exfilwatch scan -                    # read from stdin
    python -m exfilwatch scan log.jsonl --format json
    python -m exfilwatch --version

Exit codes:
    0  clean (no findings)
    1  usage / IO / parse error
    2  findings detected
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence

from . import TOOL_NAME, TOOL_VERSION
from .core import analyze, parse_log, to_sarif
from . import feeds as _feeds

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_FINDINGS = 2

_SEV_ORDER = {"high": 0, "medium": 1, "low": 2}


def _read_lines(path: str) -> list[str]:
    if path == "-":
        return sys.stdin.read().splitlines()
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read().splitlines()


def _print_table(findings: list, stream) -> None:
    if not findings:
        print("No exfiltration indicators detected.", file=stream)
        return
    header = f"{'SEV':<7} {'DETECTOR':<10} {'SCORE':>6}  {'SRC':<16} -> {'DST':<28} SUMMARY"
    print(header, file=stream)
    print("-" * len(header), file=stream)
    for f in findings:
        print(
            f"{f.severity:<7} {f.detector:<10} {f.score:>6.3f}  "
            f"{f.src:<16} -> {f.dst:<28} {f.summary}",
            file=stream,
        )
    print(f"\n{len(findings)} finding(s).", file=stream)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Detect DNS/HTTP exfiltration patterns (entropy, beaconing, tunneling) in logs.",
    )
    parser.add_argument(
        "--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Analyze a JSONL log file (or '-' for stdin).")
    scan.add_argument("logfile", help="Path to newline-delimited JSON log, or '-' for stdin.")
    scan.add_argument(
        "--format", choices=["table", "json", "sarif"], default="table",
        help="Output format: table (human), json (SIEM), sarif (code-scanning/CI).",
    )
    scan.add_argument(
        "--entropy-threshold", type=float, default=3.5,
        help="Bits/char above which a label is suspicious (default 3.5).",
    )
    scan.add_argument(
        "--beacon-min-events", type=int, default=4,
        help="Minimum callbacks to evaluate beaconing (default 4).",
    )
    scan.add_argument(
        "--beacon-max-jitter", type=float, default=0.15,
        help="Max interval coefficient-of-variation to call a beacon (default 0.15).",
    )
    scan.add_argument(
        "--dns-max-len", type=int, default=52,
        help="DNS name length above which it is flagged as oversized (default 52).",
    )
    scan.add_argument(
        "--enrich", action="store_true",
        help="Cross-reference finding destinations against abuse.ch Feodo C2 + "
             "ThreatFox IOC feeds; confirmed C2 hits are bumped to high.",
    )
    scan.add_argument(
        "--offline", action="store_true",
        help="With --enrich: serve threat-intel feeds from the local cache only "
             "(air-gap mode; never touches the network).",
    )

    # feeds: manage the bundled threat-intel feeds (edge / air-gap deployable)
    fp = sub.add_parser(
        "feeds", help="List / update / fetch the threat-intel feeds exfilwatch consumes."
    )
    fp.add_argument(
        "action", choices=["list", "update", "get"],
        help="list = show consumed feeds; update = fetch+cache; get = print cached/fetched.",
    )
    fp.add_argument(
        "feed", nargs="?",
        help=f"Feed id for get/update (one of: {', '.join(_feeds.FEED_IDS)}).",
    )
    fp.add_argument(
        "--offline", action="store_true",
        help="Serve from the local cache only; never touch the network (air-gap).",
    )
    return parser


def _cmd_feeds(args) -> int:
    """exfilwatch feeds list|update|get <id> [--offline] — restricted to the
    feed ids this tool actually consumes (feodo-c2, threatfox)."""
    allowed = _feeds.FEED_IDS
    if args.action == "list":
        catalog = _feeds._df.load_catalog()
        by_id = {f["id"]: f for f in catalog.get("feeds", [])}
        print("threat-intel feeds consumed by exfilwatch:")
        for fid in allowed:
            f = by_id.get(fid, {})
            age = _feeds._df.cached_age_hours(fid)
            fresh = "uncached" if age is None else f"{age:.1f}h old"
            print(f"  {fid:12} [{fresh:>10}]  {f.get('name', '?')}")
            print(f"               {f.get('url', '')}")
        return EXIT_OK

    fid = args.feed
    if not fid:
        print(f"error: '{args.action}' needs a feed id ({', '.join(allowed)})",
              file=sys.stderr)
        return EXIT_ERROR
    if fid not in allowed:
        print(f"error: feed {fid!r} is not consumed by exfilwatch; "
              f"allowed: {', '.join(allowed)}", file=sys.stderr)
        return EXIT_ERROR

    if args.action == "update":
        try:
            path = _feeds._df.update(fid)
        except (KeyError, ConnectionError) as e:
            print(f"error: {e}", file=sys.stderr)
            return EXIT_ERROR
        print(f"updated {fid} -> {path} ({path.stat().st_size} bytes)")
        return EXIT_OK

    # get
    try:
        data = _feeds._df.get(fid, offline=args.offline)
    except (KeyError, FileNotFoundError, ConnectionError) as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_ERROR
    print(json.dumps(data, indent=2)[:4000] if isinstance(data, (dict, list))
          else str(data)[:4000])
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "feeds":
        return _cmd_feeds(args)

    if args.command == "scan":
        try:
            lines = _read_lines(args.logfile)
        except OSError as e:
            print(f"error: cannot read {args.logfile!r}: {e}", file=sys.stderr)
            return EXIT_ERROR
        try:
            events = parse_log(lines)
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            return EXIT_ERROR

        findings = analyze(
            events,
            entropy_threshold=args.entropy_threshold,
            beacon_min_events=args.beacon_min_events,
            beacon_max_jitter=args.beacon_max_jitter,
            dns_max_len=args.dns_max_len,
        )

        intel: dict = {}
        if getattr(args, "enrich", False):
            try:
                intel = _feeds.enrich(findings, offline=args.offline)
                findings.sort(key=lambda f: f.score, reverse=True)
            except FileNotFoundError as e:
                print(f"error: --enrich --offline but feed not cached: {e}\n"
                      f"  run: exfilwatch feeds update feodo-c2 threatfox",
                      file=sys.stderr)
                return EXIT_ERROR
            except (ConnectionError, ValueError) as e:
                print(f"error: enrichment failed: {e}", file=sys.stderr)
                return EXIT_ERROR

        if args.format == "json":
            payload = {
                "tool": TOOL_NAME,
                "version": TOOL_VERSION,
                "events_analyzed": len(events),
                "finding_count": len(findings),
                "findings": [f.to_dict() for f in findings],
            }
            if getattr(args, "enrich", False):
                payload["intel_matches"] = {
                    dst: [h.to_dict() for h in hits] for dst, hits in intel.items()
                }
            print(json.dumps(payload, indent=2, sort_keys=True))
        elif args.format == "sarif":
            log_uri = None if args.logfile == "-" else args.logfile
            sarif = to_sarif(
                findings,
                tool_name=TOOL_NAME,
                tool_version=TOOL_VERSION,
                log_uri=log_uri,
            )
            print(json.dumps(sarif, indent=2, sort_keys=True))
        else:
            _print_table(findings, sys.stdout)
            if getattr(args, "enrich", False):
                if intel:
                    print("\nThreat-intel attribution (abuse.ch Feodo C2 / ThreatFox):",
                          file=sys.stdout)
                    for dst, hits in intel.items():
                        top = hits[0]
                        print(f"  {dst:28} -> {top.malware} "
                              f"[{top.feed}, conf {top.confidence}]", file=sys.stdout)
                else:
                    print("\nNo destinations matched the threat-intel feeds.",
                          file=sys.stdout)

        return EXIT_FINDINGS if findings else EXIT_OK

    parser.print_help(sys.stderr)
    return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
