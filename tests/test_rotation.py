import asyncio
import os
from unittest.mock import AsyncMock, patch

from lanmess_files.crypto import (
    generate_ed25519_private,
    x25519_generate,
)
from lanmess_files.database import Database
from lanmess_files.tui import LanMessApp


class _NoDiscovery:
    def find_by_name(self, name):
        return None


class _FakeApp:
    def __init__(self, db):
        self.db = db
        self.user_name = "alice"
        self.ed_private = generate_ed25519_private()
        self.ed_public = self.ed_private.public_key()
        self.x25519_private = x25519_generate()
        self.x25519_public = self.x25519_private.public_key()
        self.discovery = _NoDiscovery()
        self._pending_rotates = {}
        self.notifications = []

    def notify(self, msg, **kw):
        self.notifications.append(msg)

    def _audit(self, *a, **k):
        pass

    def _resolve_peer_address(self, contact):
        return ("127.0.0.1", 50510)


_FakeApp.rotate_keys = LanMessApp.rotate_keys


def _setup(db_path):
    db = Database(db_path)
    db.create_identity(
        name="alice", master=os.urandom(32), group_key=os.urandom(32),
        ed_private_hex="00"*32, ed_public_hex="11"*32,
        totp_secret_hex="22"*20, tcp_port=50510,
        x25519_private_hex="33"*32, x25519_public_hex="44"*32
    )
    db.upsert_contact(
        "bob", "10.0.0.5", 50520, "aa" * 32, "bb" * 32
    )
    return db


def test_update_contact_keys(db_path):
    db = Database(db_path)
    db.create_identity(
        name="alice", master=os.urandom(32), group_key=os.urandom(32),
        ed_private_hex="00"*32, ed_public_hex="11"*32,
        totp_secret_hex="22"*20, tcp_port=50510,
        x25519_private_hex="33"*32, x25519_public_hex="44"*32
    )
    db.upsert_contact("bob", "10.0.0.5", 50520, "aa"*32, "bb"*32)
    c = db.get_contact("bob")
    assert c["ed_public_hex"] == "aa"*32
    db.update_contact_keys("bob", "cc"*32, "dd"*32)
    c2 = db.get_contact("bob")
    assert c2["ed_public_hex"] == "cc"*32
    assert c2["x25519_public_hex"] == "dd"*32


def test_rotate_blocked_when_pending(db_path):
    db = _setup(db_path)
    app = _FakeApp(db)
    original_ed_priv = app.ed_private
    original_ed_hex = db.get_identity()["ed_public_hex"]
    app._pending_rotates["bob"] = {"type": "ROTATE"}
    with patch(
        "lanmess_files.tui.send_request",
        new_callable=AsyncMock,
    ) as mock_send:
        asyncio.run(LanMessApp.rotate_keys(app))
    assert not mock_send.called
    assert any(
        "Cannot rotate" in n for n in app.notifications
    )
    assert app.ed_private is original_ed_priv
    assert db.get_identity()["ed_public_hex"] == original_ed_hex


def test_rotate_proceeds_when_pending_empty(db_path):
    db = _setup(db_path)
    app = _FakeApp(db)
    original_ed_hex = db.get_identity()["ed_public_hex"]
    with patch(
        "lanmess_files.tui.send_request",
        new_callable=AsyncMock,
    ) as mock_send:
        mock_send.return_value = {"type": "OK"}
        asyncio.run(LanMessApp.rotate_keys(app))
    new_ed_hex = db.get_identity()["ed_public_hex"]
    assert new_ed_hex != original_ed_hex
    assert "bob" not in app._pending_rotates
    assert any(
        "rotated" in n.lower() for n in app.notifications
    )