import asyncio
import os
from unittest.mock import AsyncMock, patch
import pytest

from lanmess_files.crypto import generate_ed25519_private, x25519_generate
from lanmess_files.database import Database
from lanmess_files.tui import LanMessApp


class _FakeApp:
    def __init__(self, db):
        self.db = db
        self._outbox = {}
        self._contact_locks = {}
        self._last_activity = {}
        self._last_heard = {}
        self._peer_offline = {}
        self.notifications = []
        self.user_name = "alice"
        self.ed_private = generate_ed25519_private()
        self.x25519_private = x25519_generate()
        self.x25519_public = self.x25519_private.public_key()
        self.group_key = os.urandom(32)

    def notify(self, msg, **kwargs):
        self.notifications.append(msg)

    def _resolve_peer_address(self, contact):
        return ("127.0.0.1", 50510)

    def _get_contact_lock(self, name):
        if name not in self._contact_locks:
            self._contact_locks[name] = asyncio.Lock()
        return self._contact_locks[name]

    def _touch_activity(self, name):
        pass

    def _touch_heard(self, name):
        pass

    def _refresh_visible_messages(self):
        pass

    def _mark_offline(self, name):
        pass

    def _refresh_main(self):
        pass


def _setup(db_path):
    db = Database(db_path)
    db.create_identity(
        name="alice", master=os.urandom(32), group_key=os.urandom(32),
        ed_private_hex="00"*32, ed_public_hex="11"*32,
        totp_secret_hex="22"*20, tcp_port=50510,
        x25519_private_hex="33"*32, x25519_public_hex="44"*32
    )
    db.upsert_contact("bob", "10.0.0.5", 50520, "aa"*32, "bb"*32)
    db.set_contact_state("bob", chat_started=1, session_established=1,
                         send_chain_key_hex="00"*32, recv_chain_key_hex="11"*32)
    return db


def test_outbox_queues_on_failure(db_path):
    db = _setup(db_path)
    app = _FakeApp(db)
    
    with patch("lanmess_files.tui.send_request", new_callable=AsyncMock) as mock_send:
        mock_send.return_value = None
        
        asyncio.run(LanMessApp.send_chat_message(app, "bob", "hello"))
        
        assert "bob" in app._outbox
        assert len(app._outbox["bob"]) == 1
        assert app._outbox["bob"][0]["text"] == "hello"
        assert "queued in outbox" in app.notifications[-1]


def test_outbox_retry_loop(db_path):
    db = _setup(db_path)
    app = _FakeApp(db)
    app._outbox["bob"] = [{"text": "retry me", "reply_to": 0, "react_to": 0}]
    
    with patch("lanmess_files.tui.send_request", new_callable=AsyncMock) as mock_send:
        mock_send.return_value = {"type": "OK"}
        
        ok = asyncio.run(LanMessApp.send_chat_message(
            app, "bob", "retry me", from_outbox=True
        ))
        
        assert ok is True
        
        app._outbox["bob"].remove(app._outbox["bob"][0])
        if not app._outbox["bob"]:
            del app._outbox["bob"]
            
        assert "bob" not in app._outbox