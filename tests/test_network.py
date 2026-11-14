import asyncio

import pytest

from lanmess_files.config import MAX_FRAME_SIZE
from lanmess_files.network import Server, send_request


def test_send_request_unreachable():
    result = asyncio.run(
        send_request("127.0.0.1", 1, {"type": "X"}, timeout=0.5)
    )
    assert result is None


def test_server_roundtrip():
    async def _run():
        received = []

        async def handler(msg):
            received.append(msg)
            return {"type": "OK", "echo": msg.get("x")}

        srv = Server(0, handler)
        await srv.start()
        try:
            port = srv.server.sockets[0].getsockname()[1]
            result = await send_request(
                "127.0.0.1",
                port,
                {"type": "X", "x": 42},
                timeout=2.0,
            )
            assert result == {"type": "OK", "echo": 42}
            assert len(received) == 1
            assert received[0]["x"] == 42
            assert received[0]["type"] == "X"
        finally:
            await srv.stop()

    asyncio.run(_run())


def test_server_adds_peer_ip():
    async def _run():
        seen_peer_ips = []

        async def handler(msg):
            seen_peer_ips.append(msg.get("_peer_ip"))
            return {"type": "OK"}

        srv = Server(0, handler)
        await srv.start()
        try:
            port = srv.server.sockets[0].getsockname()[1]
            await send_request(
                "127.0.0.1",
                port,
                {"type": "X"},
                timeout=2.0,
            )
            assert seen_peer_ips == ["127.0.0.1"]
        finally:
            await srv.stop()

    asyncio.run(_run())


def test_server_drops_oversize_frame():
    async def _run():
        received = []

        async def handler(msg):
            received.append(msg)
            return {"type": "OK"}

        srv = Server(0, handler)
        await srv.start()
        try:
            port = srv.server.sockets[0].getsockname()[1]
            big = "x" * (MAX_FRAME_SIZE + 1000)
            result = await send_request(
                "127.0.0.1",
                port,
                {"type": "X", "big": big},
                timeout=1.0,
            )
            assert result is None
            assert received == []
        finally:
            await srv.stop()

    asyncio.run(_run())


def test_server_handles_concurrent_connections():
    async def _run():
        counter = {"n": 0}

        async def handler(msg):
            counter["n"] += 1
            return {"type": "OK"}

        srv = Server(0, handler)
        await srv.start()
        try:
            port = srv.server.sockets[0].getsockname()[1]
            tasks = [
                send_request(
                    "127.0.0.1", port, {"type": "X"}, timeout=2.0
                )
                for _ in range(5)
            ]
            results = await asyncio.gather(*tasks)
            assert all(r == {"type": "OK"} for r in results)
            assert counter["n"] == 5
        finally:
            await srv.stop()

    asyncio.run(_run())