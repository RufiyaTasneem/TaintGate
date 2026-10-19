
import asyncio
import sys
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


SERVER_FILE = (
    Path(__file__).resolve().parents[1]
    / "gateway"
    / "mock_server.py"
)


@pytest.mark.asyncio
async def test_mock_mcp_tools():
    server = StdioServerParameters(
        command=sys.executable,
        args=[str(SERVER_FILE)],
    )

    async with stdio_client(server) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()

            tools = await session.list_tools()
            tool_names = {tool.name for tool in tools.tools}

            assert "read_document" in tool_names
            assert "send_test_email" in tool_names

            result = await session.call_tool(
                "read_document",
                {"document_name": "meeting_notes.txt"},
            )

            assert not result.isError
            assert "Friday at 10 AM" in result.content[0].text

            print("Discovered tools:", sorted(tool_names))
            print("Mock document read successfully.")


if __name__ == "__main__":
    asyncio.run(test_mock_mcp_tools())
