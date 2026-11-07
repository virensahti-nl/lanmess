import asyncio
import json

from .config import (
    MAX_FRAME_SIZE,
    MAX_SERVER_CONNECTIONS,
    REQUEST_TIMEOUT,
)


async def send_request(
    ip, port, payload, timeout=REQUEST_TIMEOUT
):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                ip, port, limit=MAX_FRAME_SIZE
            ),
            timeout=timeout,
        )
    except Exception:
        return None
    try:
        writer.write(
            (json.dumps(payload) + "\n").encode("utf-8")
        )
        await writer.drain()
        try:
            line = await asyncio.wait_for(
                reader.readline(), timeout=timeout
            )
        except (asyncio.LimitOverrunError, ValueError):
            return None
        if not line:
            return None
        try:
            return json.loads(line.decode("utf-8"))
        except Exception:
            return None
    except Exception:
        return None
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


class Server:
    def __init__(
        self,
        port,
        handler,
        max_connections=MAX_SERVER_CONNECTIONS,
    ):
        self.port = port
        self.handler = handler
        self.server = None
        self._sem = asyncio.Semaphore(max_connections)

    async def start(self):
        self.server = await asyncio.start_server(
            self._client,
            "0.0.0.0",
            self.port,
            limit=MAX_FRAME_SIZE,
        )

    async def _client(self, reader, writer):
        if self._sem.locked():
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            return
        async with self._sem:
            await self._handle(reader, writer)

    async def _handle(self, reader, writer):
        try:
            try:
                line = await asyncio.wait_for(
                    reader.readline(), timeout=10.0
                )
            except (asyncio.LimitOverrunError, ValueError):
                return
            if not line:
                return
            try:
                msg = json.loads(line.decode("utf-8"))
            except Exception:
                return
            if not isinstance(msg, dict):
                return
            peer = writer.get_extra_info("peername")
            if peer:
                msg["_peer_ip"] = peer[0]
            resp = await self.handler(msg)
            if resp is not None:
                out = (json.dumps(resp) + "\n").encode("utf-8")
                if len(out) > MAX_FRAME_SIZE:
                    out = (
                        json.dumps({"type": "ERROR"}) + "\n"
                    ).encode("utf-8")
                writer.write(out)
                await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def stop(self):
        if self.server is not None:
            self.server.close()
            try:
                await self.server.wait_closed()
            except Exception:
                pass
            self.server = None