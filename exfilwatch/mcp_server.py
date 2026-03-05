"""EXFILWATCH MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from exfilwatch.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-exfilwatch[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-exfilwatch[mcp]'")
        return 1
    app = FastMCP("exfilwatch")

    @app.tool()
    def exfilwatch_scan(target: str) -> str:
        """Detect DNS/HTTP exfiltration patterns (entropy, beaconing) in logs. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
