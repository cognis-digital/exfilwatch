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
from .core import analyze, parse_log

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
        "--format", choices=["table", "json"], default="table", help="Output format."
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
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

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

        if args.format == "json":
            payload = {
                "tool": TOOL_NAME,
                "version": TOOL_VERSION,
                "events_analyzed": len(events),
                "finding_count": len(findings),
                "findings": [f.to_dict() for f in findings],
            }
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            _print_table(findings, sys.stdout)

        return EXIT_FINDINGS if findings else EXIT_OK

    parser.print_help(sys.stderr)
    return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
