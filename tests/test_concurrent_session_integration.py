
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


def get_free_port():
    """Ask the operating system for an available TCP port."""
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
    """Wait until the gateway accepts connections."""
    for _ in range(60):
        if process.poll() is not None:
            raise RuntimeError(
                f"Gateway exited unexpectedly: {process.returncode}"
            )

        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(HOST, port),
                timeout=1,
            )
            writer.close()
            await writer.wait_closed()
            return
        except (OSError, asyncio.TimeoutError):
            await asyncio.sleep(0.5)

    raise TimeoutError("Gateway did not start within 30 seconds.")


async def run_concurrent_session_test():
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

        # Keep Session B alive while Session A is terminated.
        async with streamable_http_client(gateway_url) as (
            read_b, write_b, get_session_id_b
        ):
            async with ClientSession(read_b, write_b) as session_b:
                await session_b.initialize()

                session_b_id = get_session_id_b()
                assert session_b_id is not None

                async with streamable_http_client(gateway_url) as (
                    read_a, write_a, get_session_id_a
                ):
                    async with ClientSession(
                        read_a, write_a
                    ) as session_a:
                        await session_a.initialize()

                        session_a_id = get_session_id_a()
                        assert session_a_id is not None
                        assert session_a_id != session_b_id, (
                            "Both MCP clients received the same session ID."
                        )

                        # Both sessions read different documents concurrently.
                        read_a_result, read_b_result = await asyncio.gather(
                            session_a.call_tool(
                                "read_document",
                                {"document_name": "project_update.txt"},
                            ),
                            session_b.call_tool(
                                "read_document",
                                {"document_name": "meeting_notes.txt"},
                            ),
                        )

                        assert not read_a_result.isError
                        assert not read_b_result.isError

                        # Both sessions attempt email actions concurrently.
                        result_a, result_b = await asyncio.gather(
                            session_a.call_tool(
                                "send_test_email",
                                {
                                    "recipient": "teammate@example.com",
                                    "subject": "Project update",
                                    "body": (
                                        "Project status: "
                                        "development is 80% complete."
                                    ),
                                },
                            ),
                            session_b.call_tool(
                                "send_test_email",
                                {
                                    "recipient": "teammate@example.com",
                                    "subject": "Meeting notes",
                                    "body": (
                                        "Please prepare the room for Monday."
                                    ),
                                },
                            ),
                        )

                        response_a = get_response(result_a)
                        response_b = get_response(result_b)

                        assert "BLOCKED by TaintGate" in response_a, (
                            f"Session A was not blocked: {response_a}"
                        )

                        assert "SIMULATED EMAIL ACTION" in response_b, (
                            "Session B's benign content was blocked: "
                            f"{response_b}"
                        )

                # Session A has now terminated.
                # Session B must remain functional.
                result_after_termination = await session_b.call_tool(
                    "send_test_email",
                    {
                        "recipient": "teammate@example.com",
                        "subject": "Follow-up",
                        "body": "The next meeting is on Monday.",
                    },
                )

                response_after_termination = get_response(
                    result_after_termination
                )

                assert (
                    "SIMULATED EMAIL ACTION"
                    in response_after_termination
                ), (
                    "Session B stopped working after Session A terminated: "
                    f"{response_after_termination}"
                )

    finally:
        process.terminate()

        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def test_concurrent_mcp_sessions_remain_isolated():
    asyncio.run(run_concurrent_session_test())
