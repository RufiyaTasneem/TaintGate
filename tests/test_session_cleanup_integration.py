
import asyncio
import gc
import importlib.util
import socket
import sys
import time
import weakref
from pathlib import Path

import uvicorn
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


ROOT = Path(__file__).resolve().parents[1]
GATEWAY_DIR = ROOT / "gateway"
GATEWAY_PATH = GATEWAY_DIR / "gateway.py"


def load_gateway():
    """Load the gateway with its existing sibling-module imports."""
    gateway_dir = str(GATEWAY_DIR)

    if gateway_dir not in sys.path:
        sys.path.insert(0, gateway_dir)

    spec = importlib.util.spec_from_file_location(
        "taintgate_cleanup_gateway",
        GATEWAY_PATH,
    )

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    return module


async def wait_until(predicate, timeout=10):
    """Wait until a condition becomes true."""
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        if predicate():
            return True

        await asyncio.sleep(0.05)

    return predicate()


async def run_session_cleanup_test(gw, session_refs, registry_refs):
    app = gw.mcp.streamable_http_app()
    manager = gw.mcp.session_manager

    # Let the operating system assign an available port.
    server_socket = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    )
    server_socket.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1,
    )
    server_socket.bind(("127.0.0.1", 0))
    server_socket.listen()
    server_socket.setblocking(False)

    port = server_socket.getsockname()[1]
    gateway_url = f"http://127.0.0.1:{port}/mcp"

    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=port,
        lifespan="on",
        log_level="error",
        access_log=False,
    )
    server = uvicorn.Server(config)

    server_task = asyncio.create_task(
        server.serve(sockets=[server_socket])
    )

    try:
        started = await wait_until(lambda: server.started)

        assert started, "Uvicorn server did not start."

        async with streamable_http_client(gateway_url) as (
            read_stream,
            write_stream,
            get_session_id,
        ):
            async with ClientSession(
                read_stream,
                write_stream,
            ) as client:
                await client.initialize()

                session_id = get_session_id()
                assert session_id is not None

                # Reading a document creates the session registry.
                result = await client.call_tool(
                    "read_document",
                    {"document_name": "project_update.txt"},
                )

                assert not result.isError, (
                    "Document read failed."
                )

                assert session_id in manager._server_instances, (
                    "Session was not registered with the manager."
                )

                assert len(session_refs) == 1
                assert len(registry_refs) == 1

                assert session_refs[0]() is not None
                assert registry_refs[0]() is not None

        # Exiting both client contexts sends DELETE to the server.

        removed = await wait_until(
            lambda: session_id not in manager._server_instances
        )

        assert removed, (
            "Terminated session remained in the session manager."
        )

        # Allow the server task and request references to unwind.
        collected = await wait_until(
            lambda: (
                gc.collect() is not None
                and session_refs[0]() is None
                and registry_refs[0]() is None
            ),
            timeout=10,
        )

        assert collected, (
            "Session or registry is still strongly referenced "
            "after session termination."
        )

    finally:
        server.should_exit = True

        try:
            await asyncio.wait_for(server_task, timeout=10)
        except asyncio.TimeoutError:
            server_task.cancel()
            await asyncio.gather(
                server_task,
                return_exceptions=True,
            )


def test_terminated_mcp_session_releases_registry(monkeypatch):
    gw = load_gateway()

    session_refs = []
    registry_refs = []

    original_get_registry = gw.get_registry

    def track_registry(ctx):
        registry = original_get_registry(ctx)

        if ctx is not None and not session_refs:
            session_refs.append(weakref.ref(ctx.session))
            registry_refs.append(weakref.ref(registry))

        return registry

    monkeypatch.setattr(gw, "get_registry", track_registry)

    asyncio.run(
        run_session_cleanup_test(
            gw,
            session_refs,
            registry_refs,
        )
    )
