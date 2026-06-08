"""EXFILWATCH - defensive detection of DNS/HTTP exfiltration patterns.

Analysis/triage/detection only. No attack capability. Standard library only.

Detects:
  * High-entropy DNS labels / HTTP paths (data-tunneling indicator)
  * Beaconing: low-jitter periodic callbacks to a single destination
  * Long / oversized DNS queries (encoded payload smuggling)

In the spirit of RITA (Real Intelligence Threat Analytics).
"""
from .core import (
    LogEvent,
    Finding,
    shannon_entropy,
    detect_entropy,
    detect_beaconing,
    detect_long_dns,
    analyze,
    parse_log,
)

TOOL_NAME = "exfilwatch"
TOOL_VERSION = "1.0.0"

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "LogEvent",
    "Finding",
    "shannon_entropy",
    "detect_entropy",
    "detect_beaconing",
    "detect_long_dns",
    "analyze",
    "parse_log",
]
