"""Registered development MCP server used to verify the PAJIN bridge."""

from typing import Any

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("PAJIN Demo Security Server")


@mcp.tool()
def inspect_text(text: str) -> dict[str, Any]:
    """Inspect text for a simple instruction-hijacking marker."""

    suspicious = "ignore previous" in text.lower()
    return {
        "vulnerable": suspicious,
        "observation": (
            "untrusted text contains an instruction-hijacking pattern"
            if suspicious
            else "no instruction-hijacking pattern detected"
        ),
    }


if __name__ == "__main__":
    mcp.run(transport="stdio")
