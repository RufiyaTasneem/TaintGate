
import sys
import asyncio
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.server.fastmcp import FastMCP

from audit import log_decision
from policy import check_email_policy
from taint import register_untrusted, find_tainted_sources

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from rag.answer import answer_question

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

    async with stdio_client(server) as (
        read_stream,
        write_stream,
    ):
        async with ClientSession(
            read_stream,
            write_stream,
        ) as session:
            await session.initialize()

            result = await session.call_tool(
                tool_name,
                arguments,
            )

            if result.isError:
                raise RuntimeError(
                    f"Upstream tool failed: {tool_name}"
                )

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

    # 1. Check provenance first and preserve source filenames.
    tainted_sources = find_tainted_sources(body)

    if tainted_sources:
        source_names = sorted({
            source
            for record in tainted_sources
            for source in record.sources
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

    # 2. Independently block a known risky address in the body.
    risky_body_addresses = {
        "attacker@example.com",
    }

    normalized_body = body.lower()

    matched_risky_addresses = [
        address
        for address in risky_body_addresses
        if address in normalized_body
    ]

    if matched_risky_addresses:
        reason = "Email body contains a known blocked address."

        log_decision(
            "send_test_email",
            "BLOCKED",
            reason,
            reason_code="RISKY_ADDRESS_IN_BODY",
        )

        return f"BLOCKED by TaintGate: {reason}"

    # 3. Enforce the recipient policy.
    policy_decision = check_email_policy(recipient)

    if not policy_decision.allowed:
        log_decision(
            "send_test_email",
            "BLOCKED",
            policy_decision.reason,
            reason_code="RECIPIENT_POLICY",
        )

        return (
            f"BLOCKED by TaintGate: "
            f"{policy_decision.reason}"
        )

    # 4. Record the allow decision.
    log_decision(
        "send_test_email",
        "ALLOWED",
        "Taint and recipient checks passed.",
        reason_code="POLICY_PASSED",
    )

    # 5. Forward only when all checks pass.
    return await call_upstream(
        "send_test_email",
        {
            "recipient": recipient,
            "subject": subject,
            "body": body,
        },
    )


@mcp.tool()
async def ask_security_question(question: str) -> str:
    """Answer security questions using TaintGate's local knowledge base."""

    result = await asyncio.to_thread(
        answer_question,
        question,
    )

    answer = result["answer"]
    sources = result["sources"]

    if sources:
        answer += "\n\nSources: " + ", ".join(sources)

    return answer


if __name__ == "__main__":
    mcp.run(transport="stdio")
