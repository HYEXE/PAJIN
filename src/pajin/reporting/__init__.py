"""Human-readable and machine-readable report generation."""

from pajin.reporting.markdown import (
    escape_markdown_text,
    markdown_code_span,
    render_markdown_report,
)

__all__ = ["escape_markdown_text", "markdown_code_span", "render_markdown_report"]
