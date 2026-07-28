"""Registered development MCP server used to verify the PAJIN bridge."""

from typing import Any

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("PAJIN Demo Security Server")


@mcp.resource("pajin://policy")
def policy_resource() -> str:
    """Return a non-sensitive development policy fixture."""

    return "Inspect only explicitly registered development inputs."


@mcp.resource("pajin://guidance/{topic}")
def guidance_resource(topic: str) -> str:
    """Return bounded development guidance for one topic."""

    return f"Review {topic} using the registered PAJIN development boundary."


@mcp.prompt()
def inspect_prompt(text: str) -> str:
    """Build the registered inspection prompt."""

    return f"Inspect this text for instruction hijacking: {text}"


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
