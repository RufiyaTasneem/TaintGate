
import sys
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.server.fastmcp import FastMCP
from audit import log_decision
from policy import check_email_policy
from taint import register_untrusted, find_tainted_sources

mcp = FastMCP("TaintGate Gateway")

MOCK_SERVER_PATH = (
    Path(__file__).resolve().parent / "mock_server.py"
)


async def call_upstream(
    tool_name: str,
    arguments: dict[str, Any],
) -> str:
    """Call the mock MCP server as an MCP client."""

    server = StdioServerParameters(
        command=sys.executable,
        args=[str(MOCK_SERVER_PATH)],
    )

    async with stdio_client(server) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()

            result = await session.call_tool(
                tool_name,
                arguments,
            )

            if result.isError:
                raise RuntimeError(f"Upstream tool failed: {tool_name}")

            return "\n".join(
                item.text
                for item in result.content
                if hasattr(item, "text")
            )


@mcp.tool()
async def read_document(document_name: str) -> str:
    """Read a document and track its untrusted provenance."""

    content = await call_upstream(
        "read_document",
        {"document_name": document_name},
    )

    register_untrusted(content, document_name)
    return content




@mcp.tool()
async def send_test_email(
    recipient: str,
    subject: str,
    body: str,
) -> str:
    """Send a simulated email, subject to TaintGate policy."""

    # Check for untrusted content and identify its sources.
    tainted_sources = find_tainted_sources(body)

    if tainted_sources:
        source_names = sorted({
            record.source for record in tainted_sources
        })

        reason = "Email body contains untrusted content."
        log_decision(
            "send_test_email",
            "BLOCKED",
            reason,
            reason_code="UNTRUSTED_CONTENT",
            sources=source_names,
        )

        return (
            "BLOCKED by TaintGate: "
            f"{reason} Sources: {', '.join(source_names)}"
        )

    # Apply the recipient policy.
    policy_decision = check_email_policy(recipient)

    if not policy_decision.allowed:
        log_decision(
            "send_test_email",
            "BLOCKED",
            policy_decision.reason,
            reason_code="RECIPIENT_POLICY",
        )
        return f"BLOCKED by TaintGate: {policy_decision.reason}"

    # Record the allow decision.
    log_decision(
        "send_test_email",
        "ALLOWED",
        "Taint and recipient checks passed.",
        reason_code="POLICY_PASSED",
    )

    # Forward the call only if both checks pass.
    return await call_upstream(
        "send_test_email",
        {
            "recipient": recipient,
            "subject": subject,
            "body": body,
        },
    )


if __name__ == "__main__":
    mcp.run(transport="stdio")