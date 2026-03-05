"""EXFILWATCH — Detect DNS/HTTP exfiltration patterns (entropy, beaconing) in logs."""
from exfilwatch.core import scan, TOOL_NAME, TOOL_VERSION
__all__ = ["scan", "TOOL_NAME", "TOOL_VERSION"]
