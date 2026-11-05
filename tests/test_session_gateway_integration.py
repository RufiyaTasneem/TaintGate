
import asyncio
import os
import socket
import subprocess
import sys
from pathlib import Path

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


GATEWAY_PATH = (
    Path(__file__).resolve().parents[1]
    / "gateway"
    / "gateway.py"
)

HOST = "127.0.0.1"
TEST_BODY = "Project status: development is 80% complete."


def get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((HOST, 0))
        return sock.getsockname()[1]


def get_response(result):
    return "\n".join(
        item.text
        for item in result.content
        if hasattr(item, "text")
    )


async def wait_for_gateway(process, port):
    for _ in range(60):
        if process.poll() is not None:
            raise RuntimeError(
                f"Gateway exited unexpectedly: {process.returncode}"
            )

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(HOST, port),
                timeout=1,
            )
            writer.close()
            await writer.wait_closed()
            return
        except (OSError, asyncio.TimeoutError):
            await asyncio.sleep(0.5)

    raise TimeoutError("Gateway did not start within 30 seconds.")


async def run_cross_session_test():
    port = get_free_port()
    gateway_url = f"http://{HOST}:{port}/mcp"

    env = os.environ.copy()
    env["TAINTGATE_TRANSPORT"] = "streamable-http"
    env["TAINTGATE_PORT"] = str(port)

    process = subprocess.Popen(
        [sys.executable, str(GATEWAY_PATH)],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        await wait_for_gateway(process, port)

        async with streamable_http_client(gateway_url) as (
            read_a, write_a, get_session_id_a
        ):
            async with ClientSession(read_a, write_a) as session_a:
                await session_a.initialize()
                session_a_id = get_session_id_a()
                assert session_a_id is not None

                async with streamable_http_client(gateway_url) as (
                    read_b, write_b, get_session_id_b
                ):
                    async with ClientSession(read_b, write_b) as session_b:
                        await session_b.initialize()
                        session_b_id = get_session_id_b()
                        assert session_b_id is not None
                        assert session_a_id != session_b_id, (
                            "Both MCP clients received the same session ID."
                        )

                        # Session A reads the untrusted document.
                        await session_a.call_tool(
                            "read_document",
                            {"document_name": "project_update.txt"},
                        )

                        # The same text must be blocked in Session A.
                        result_a = await session_a.call_tool(
                            "send_test_email",
                            {
                                "recipient": "teammate@example.com",
                                "subject": "Project update",
                                "body": TEST_BODY,
                            },
                        )
                        response_a = get_response(result_a)

                        assert "BLOCKED by TaintGate" in response_a, (
                            f"Session A was not blocked: {response_a}"
                        )

                        # Session B has not read the document.
                        # The same text must not inherit Session A's taint.
                        result_b = await session_b.call_tool(
                            "send_test_email",
                            {
                                "recipient": "teammate@example.com",
                                "subject": "Project update",
                                "body": TEST_BODY,
                            },
                        )
                        response_b = get_response(result_b)

                        assert "SIMULATED EMAIL ACTION" in response_b, (
                            "Session B inherited Session A's taint: "
                            f"{response_b}"
                        )

    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def test_mcp_sessions_have_isolated_taint_registries():
    asyncio.run(run_cross_session_test())
