import asyncio
import base64
import hashlib
import hmac
import json
import os
import time
from unittest.mock import AsyncMock, patch

import pytest

from lanmess_files.config import CONTROL_SIG_PREFIX
from lanmess_files.crypto import (
    ed_public_to_bytes,
    generate_ed25519_private,
    sign_bytes,
    x25519_generate,
    x25519_public_to_bytes,
)
from lanmess_files.network import Server
from lanmess_files.tui import (
    AddByIpScreen,
    LanMessApp,
    _valid_ipv4,
    _valid_port,
    get_local_ips,
)


class _FakeDB:
    def __init__(self):
        self.contacts = {}
        self.states = {}

    def get_contact(self, name):
        return self.contacts.get(name)

    def upsert_contact(
        self,
        name,
        ip,
        port,
        ed_public_hex,
        x25519_public_hex=None,
    ):
        self.contacts[name] = {
            "name": name,
            "ip": ip,
            "port": port,
            "ed_public_hex": ed_public_hex,
            "x25519_public_hex": x25519_public_hex or "",
        }

    def set_contact_state(self, name, **kwargs):
        if name not in self.states:
            self.states[name] = {}
        self.states[name].update(kwargs)


class _FakeApp:
    def __init__(self, db=None):
        self.ed_private = generate_ed25519_private()
        self.ed_public = self.ed_private.public_key()
        self.x25519_private = x25519_generate()
        self.x25519_public = self.x25519_private.public_key()
        self.user_name = "alice"
        self.tcp_port = 50510
        self.db = db or _FakeDB()
        self.notifications = []

    def notify(self, msg, **kwargs):
        self.notifications.append(msg)

    def _audit(self, *a, **k):
        pass

    def _refresh_main(self, *a, **k):
        pass

    def _refresh_visible_messages(self, *a, **k):
        pass

    def _touch_heard(self, name):
        pass


_FakeApp._valid_hex = LanMessApp._valid_hex
_FakeApp._valid_name = LanMessApp._valid_name
_FakeApp._valid_timestamp = LanMessApp._valid_timestamp
_FakeApp._valid_code = LanMessApp._valid_code
_FakeApp._check_signed = LanMessApp._check_signed
_FakeApp._signed = LanMessApp._signed
_FakeApp._build_add_request_payload = (
    LanMessApp._build_add_request_payload
)
_FakeApp._process_add_response = (
    LanMessApp._process_add_response
)


def _make_peer_response(code, peer_name, peer_sk, peer_x_sk):
    resp_challenge = os.urandom(32)
    resp_proof = hmac.new(
        code.encode("utf-8"),
        b"ACC"
        + peer_name.encode("utf-8")
        + resp_challenge,
        hashlib.sha256,
    ).digest()
    resp_fields = {
        "type": "ADD_ACCEPT",
        "to_name": peer_name,
        "to_ed_pub": ed_public_to_bytes(
            peer_sk.public_key()
        ).hex(),
        "to_x25519_pub": x25519_public_to_bytes(
            peer_x_sk.public_key()
        ).hex(),
        "challenge": base64.b64encode(
            resp_challenge
        ).decode("ascii"),
        "proof": resp_proof.hex(),
        "timestamp": int(time.time() * 1000),
    }
    body = dict(resp_fields)
    data = CONTROL_SIG_PREFIX + json.dumps(
        body, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    sig = base64.b64encode(
        sign_bytes(peer_sk, data)
    ).decode("ascii")
    return {**body, "signature": sig}


def test_valid_ipv4_accepts():
    assert _valid_ipv4("192.168.1.1")
    assert _valid_ipv4("10.0.0.1")
    assert _valid_ipv4("100.64.0.5")
    assert _valid_ipv4("0.0.0.0")
    assert _valid_ipv4("255.255.255.255")


def test_valid_ipv4_rejects():
    assert not _valid_ipv4("")
    assert not _valid_ipv4("1.2.3")
    assert not _valid_ipv4("1.2.3.4.5")
    assert not _valid_ipv4("256.1.1.1")
    assert not _valid_ipv4("1.2.3.-1")
    assert not _valid_ipv4("abc")
    assert not _valid_ipv4("1.2.3.4 ")


def test_valid_port_accepts():
    assert _valid_port("1")
    assert _valid_port("50510")
    assert _valid_port("65535")


def test_valid_port_rejects():
    assert not _valid_port("0")
    assert not _valid_port("65536")
    assert not _valid_port("")
    assert not _valid_port("abc")
    assert not _valid_port("-1")
    assert not _valid_port("50510 ")


def test_get_local_ips_returns_list():
    ips = get_local_ips()
    assert isinstance(ips, list)
    assert len(ips) >= 1
    for ip in ips:
        assert isinstance(ip, str)
        assert _valid_ipv4(ip)


def test_build_add_request_payload():
    app = _FakeApp()
    payload = app._build_add_request_payload("12345678")
    assert payload["type"] == "ADD_REQUEST"
    assert payload["from_name"] == "alice"
    assert payload["from_port"] == 50510
    assert payload["signature"]
    assert payload["challenge"]
    assert payload["proof"]
    assert len(payload["from_ed_pub"]) == 64
    assert len(payload["from_x25519_pub"]) == 64
    assert app._check_signed(payload, app.ed_public)


def test_add_by_ip_sends_to_provided_address():
    app = _FakeApp()
    mock_send = AsyncMock(return_value=None)
    with patch(
        "lanmess_files.tui.send_request", mock_send
    ):
        result = asyncio.run(
            LanMessApp.add_contact_by_ip(
                app, "10.20.30.40", 9999, "12345678"
            )
        )
    mock_send.assert_called_once()
    args = mock_send.call_args[0]
    assert args[0] == "10.20.30.40"
    assert args[1] == 9999
    assert args[2]["type"] == "ADD_REQUEST"
    assert result is False


def test_process_add_response_accept():
    app = _FakeApp()
    code = "12345678"
    peer_sk = generate_ed25519_private()
    peer_x_sk = x25519_generate()
    resp = _make_peer_response(
        code, "bob", peer_sk, peer_x_sk
    )
    result = asyncio.run(
        LanMessApp._process_add_response(
            app,
            resp,
            code,
            "10.0.0.5",
            50520,
            expected_found_name=None,
        )
    )
    assert result is True
    assert "bob" in app.db.contacts
    assert (
        app.db.contacts["bob"]["ed_public_hex"]
        == ed_public_to_bytes(peer_sk.public_key()).hex()
    )
    assert app.db.states["bob"]["pending"] == 0


def test_process_add_response_pending():
    app = _FakeApp()
    code = "12345678"
    peer_sk = generate_ed25519_private()
    peer_x_sk = x25519_generate()
    resp = _make_peer_response(
        code, "bob", peer_sk, peer_x_sk
    )
    resp["type"] = "ADD_PENDING"
    body = {
        k: v for k, v in resp.items() if k != "signature"
    }
    data = CONTROL_SIG_PREFIX + json.dumps(
        body, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    resp["signature"] = base64.b64encode(
        sign_bytes(peer_sk, data)
    ).decode("ascii")
    result = asyncio.run(
        LanMessApp._process_add_response(
            app,
            resp,
            code,
            "10.0.0.5",
            50520,
            expected_found_name=None,
        )
    )
    assert result is True
    assert app.db.states["bob"]["pending"] == 1


def test_process_add_response_unreachable():
    app = _FakeApp()
    result = asyncio.run(
        LanMessApp._process_add_response(
            app, None, "12345678", "1.2.3.4", 50510
        )
    )
    assert result is False


def test_process_add_response_rejected():
    app = _FakeApp()
    resp = {"type": "ADD_REJECT", "reason": "invalid_code"}
    result = asyncio.run(
        LanMessApp._process_add_response(
            app, resp, "12345678", "1.2.3.4", 50510
        )
    )
    assert result is False


def test_process_add_response_bad_hex():
    app = _FakeApp()
    resp = {
        "type": "ADD_ACCEPT",
        "to_ed_pub": "zz" * 32,
        "to_x25519_pub": "aa" * 32,
        "to_name": "bob",
        "challenge": base64.b64encode(
            os.urandom(32)
        ).decode(),
        "proof": "00" * 32,
        "timestamp": int(time.time() * 1000),
        "signature": "00",
    }
    result = asyncio.run(
        LanMessApp._process_add_response(
            app, resp, "12345678", "1.2.3.4", 50510
        )
    )
    assert result is False


def test_process_add_response_stale_timestamp():
    app = _FakeApp()
    code = "12345678"
    peer_sk = generate_ed25519_private()
    peer_x_sk = x25519_generate()
    resp = _make_peer_response(
        code, "bob", peer_sk, peer_x_sk
    )
    resp["timestamp"] = 1
    body = {
        k: v for k, v in resp.items() if k != "signature"
    }
    data = CONTROL_SIG_PREFIX + json.dumps(
        body, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    resp["signature"] = base64.b64encode(
        sign_bytes(peer_sk, data)
    ).decode("ascii")
    result = asyncio.run(
        LanMessApp._process_add_response(
            app, resp, code, "1.2.3.4", 50510
        )
    )
    assert result is False


def test_process_add_response_wrong_code():
    app = _FakeApp()
    peer_sk = generate_ed25519_private()
    peer_x_sk = x25519_generate()
    resp = _make_peer_response(
        "12345678", "bob", peer_sk, peer_x_sk
    )
    result = asyncio.run(
        LanMessApp._process_add_response(
            app, resp, "87654321", "1.2.3.4", 50510
        )
    )
    assert result is False
    assert "bob" not in app.db.contacts


def test_process_add_response_bad_signature():
    app = _FakeApp()
    code = "12345678"
    peer_sk = generate_ed25519_private()
    peer_x_sk = x25519_generate()
    resp = _make_peer_response(
        code, "bob", peer_sk, peer_x_sk
    )
    resp["signature"] = base64.b64encode(
        b"\x00" * 64
    ).decode("ascii")
    result = asyncio.run(
        LanMessApp._process_add_response(
            app, resp, code, "1.2.3.4", 50510
        )
    )
    assert result is False


def test_process_add_response_name_mismatch():
    app = _FakeApp()
    code = "12345678"
    peer_sk = generate_ed25519_private()
    peer_x_sk = x25519_generate()
    resp = _make_peer_response(
        code, "bob", peer_sk, peer_x_sk
    )
    result = asyncio.run(
        LanMessApp._process_add_response(
            app,
            resp,
            code,
            "1.2.3.4",
            50510,
            expected_found_name="carol",
        )
    )
    assert result is False


def test_process_add_response_rejects_self():
    app = _FakeApp()
    code = "12345678"
    peer_sk = generate_ed25519_private()
    peer_x_sk = x25519_generate()
    resp = _make_peer_response(
        code, "alice", peer_sk, peer_x_sk
    )
    result = asyncio.run(
        LanMessApp._process_add_response(
            app, resp, code, "1.2.3.4", 50510
        )
    )
    assert result is False


def test_process_add_response_rejects_key_change():
    app = _FakeApp()
    code = "12345678"
    peer_sk1 = generate_ed25519_private()
    peer_x_sk1 = x25519_generate()
    app.db.contacts["bob"] = {
        "name": "bob",
        "ed_public_hex": ed_public_to_bytes(
            peer_sk1.public_key()
        ).hex(),
    }
    peer_sk2 = generate_ed25519_private()
    peer_x_sk2 = x25519_generate()
    resp = _make_peer_response(
        code, "bob", peer_sk2, peer_x_sk2
    )
    result = asyncio.run(
        LanMessApp._process_add_response(
            app, resp, code, "1.2.3.4", 50510
        )
    )
    assert result is False


def test_end_to_end_over_loopback():
    async def run():
        code = "12345678"
        peer_name = "bob"
        peer_sk = generate_ed25519_private()
        peer_pk = peer_sk.public_key()
        peer_x_sk = x25519_generate()
        peer_x_pk = peer_x_sk.public_key()

        async def handler(msg):
            if msg.get("type") != "ADD_REQUEST":
                return {"type": "ERROR"}
            resp_challenge = os.urandom(32)
            resp_proof = hmac.new(
                code.encode("utf-8"),
                b"ACC"
                + peer_name.encode("utf-8")
                + resp_challenge,
                hashlib.sha256,
            ).digest()
            resp_fields = {
                "type": "ADD_ACCEPT",
                "to_name": peer_name,
                "to_ed_pub": ed_public_to_bytes(
                    peer_pk
                ).hex(),
                "to_x25519_pub": x25519_public_to_bytes(
                    peer_x_pk
                ).hex(),
                "challenge": base64.b64encode(
                    resp_challenge
                ).decode("ascii"),
                "proof": resp_proof.hex(),
                "timestamp": int(time.time() * 1000),
            }
            body = dict(resp_fields)
            data = CONTROL_SIG_PREFIX + json.dumps(
                body, separators=(",", ":"), sort_keys=True
            ).encode("utf-8")
            sig = base64.b64encode(
                sign_bytes(peer_sk, data)
            ).decode("ascii")
            return {**body, "signature": sig}

        server = Server(0, handler)
        await server.start()
        try:
            port = server.server.sockets[0].getsockname()[1]
            app = _FakeApp()
            result = await LanMessApp.add_contact_by_ip(
                app, "127.0.0.1", port, code
            )
            assert result is True
            assert "bob" in app.db.contacts
            assert (
                app.db.contacts["bob"]["ed_public_hex"]
                == ed_public_to_bytes(peer_pk).hex()
            )
            assert (
                app.db.contacts["bob"]["x25519_public_hex"]
                == x25519_public_to_bytes(peer_x_pk).hex()
            )
        finally:
            await server.stop()

    asyncio.run(run())


def test_end_to_end_wrong_code():
    async def run():
        code = "12345678"
        peer_name = "bob"
        peer_sk = generate_ed25519_private()
        peer_pk = peer_sk.public_key()
        peer_x_sk = x25519_generate()
        peer_x_pk = peer_x_sk.public_key()

        async def handler(msg):
            resp_challenge = os.urandom(32)
            resp_proof = hmac.new(
                code.encode("utf-8"),
                b"ACC"
                + peer_name.encode("utf-8")
                + resp_challenge,
                hashlib.sha256,
            ).digest()
            resp_fields = {
                "type": "ADD_ACCEPT",
                "to_name": peer_name,
                "to_ed_pub": ed_public_to_bytes(
                    peer_pk
                ).hex(),
                "to_x25519_pub": x25519_public_to_bytes(
                    peer_x_pk
                ).hex(),
                "challenge": base64.b64encode(
                    resp_challenge
                ).decode("ascii"),
                "proof": resp_proof.hex(),
                "timestamp": int(time.time() * 1000),
            }
            body = dict(resp_fields)
            data = CONTROL_SIG_PREFIX + json.dumps(
                body, separators=(",", ":"), sort_keys=True
            ).encode("utf-8")
            sig = base64.b64encode(
                sign_bytes(peer_sk, data)
            ).decode("ascii")
            return {**body, "signature": sig}

        server = Server(0, handler)
        await server.start()
        try:
            port = server.server.sockets[0].getsockname()[1]
            app = _FakeApp()
            result = await LanMessApp.add_contact_by_ip(
                app, "127.0.0.1", port, "87654321"
            )
            assert result is False
            assert "bob" not in app.db.contacts
        finally:
            await server.stop()

    asyncio.run(run())


def test_end_to_end_unreachable():
    app = _FakeApp()
    result = asyncio.run(
        LanMessApp.add_contact_by_ip(
            app, "127.0.0.1", 1, "12345678"
        )
    )
    assert result is False


def test_add_by_ip_screen_valid():
    screen = AddByIpScreen.__new__(AddByIpScreen)
    assert _valid_ipv4("192.168.1.1")
    assert _valid_port("50510")


def test_add_by_ip_screen_invalid_ip():
    assert not _valid_ipv4("not-an-ip")


def test_my_address_screen_fields():
    from lanmess_files.tui import MyAddressScreen

    screen = MyAddressScreen(["192.168.1.5", "100.64.0.5"], 50510)
    assert screen.ips == ["192.168.1.5", "100.64.0.5"]
    assert screen.port == 50510