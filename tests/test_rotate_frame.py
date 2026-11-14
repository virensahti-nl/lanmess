import os
import base64
import json
import time
import asyncio
import pytest

from lanmess_files.config import CONTROL_SIG_PREFIX
from lanmess_files.crypto import (
    ed_public_to_bytes, 
    sign_bytes,
    generate_ed25519_private,
)
from lanmess_files.database import Database
from lanmess_files.tui import LanMessApp


class _FakeApp:
    def __init__(self, db, sk_ed):
        self.db = db
        self.ed_private = sk_ed
        self._last_activity = {}
        self._last_heard = {}
        self._peer_offline = {}
        self._peer_typing = {}
        self._presence_success = {}
        self._presence_fail = {}
        self._last_typing_sent = {}
        self._pending_rotates = {}
        self.notifications = []

    def notify(self, msg, **kwargs):
        self.notifications.append(msg)

    def _apply_peer_ip(self, msg, name):
        pass

    def _audit(self, *args, **kwargs):
        pass

    def _refresh_main(self):
        pass

    def _refresh_visible_messages(self):
        pass

    def _touch_heard(self, name):
        self._last_heard[name] = time.time()
        self._peer_offline.pop(name, None)
        self._presence_fail.pop(name, None)

    def _mark_offline(self, name):
        self._peer_offline[name] = time.time()
        self._last_heard[name] = 0
        self._presence_success.pop(name, None)

    def _resolve_peer_address(self, contact):
        return ("127.0.0.1", 50510)

    _valid_name = LanMessApp._valid_name
    _valid_hex = LanMessApp._valid_hex
    _valid_timestamp = LanMessApp._valid_timestamp
    _check_signed = LanMessApp._check_signed
    _verify_peer_sig_no_touch = LanMessApp._verify_peer_sig_no_touch


def _setup(db_path):
    db = Database(db_path)
    old_sk_obj = generate_ed25519_private()
    old_pk = old_sk_obj.public_key()
    
    db.create_identity(
        name="alice", master=os.urandom(32), group_key=os.urandom(32),
        ed_private_hex="00"*32, ed_public_hex="11"*32,
        totp_secret_hex="22"*20, tcp_port=50510,
        x25519_private_hex="33"*32, x25519_public_hex="44"*32
    )
    
    db.upsert_contact("bob", "10.0.0.5", 50520, ed_public_to_bytes(old_pk).hex(), "bb"*32)
    db.set_contact_state("bob", chat_started=1, session_established=1)
    
    return db, old_sk_obj


def _make_rotate_msg(sk, from_name, new_ed_hex, new_x_hex):
    fields = {
        "type": "ROTATE",
        "from_name": from_name,
        "new_ed_pub": new_ed_hex,
        "new_x25519_pub": new_x_hex,
        "timestamp": int(time.time() * 1000),
    }
    data = CONTROL_SIG_PREFIX + json.dumps(fields, separators=(",", ":"), sort_keys=True).encode("utf-8")
    sig = base64.b64encode(sign_bytes(sk, data)).decode("ascii")
    return {**fields, "signature": sig}


def test_handle_rotate_updates_db(db_path):
    db, old_sk = _setup(db_path)
    app = _FakeApp(db, old_sk)
    
    new_ed_hex = "aa" * 32
    new_x_hex = "bb" * 32
    
    msg = _make_rotate_msg(old_sk, "bob", new_ed_hex, new_x_hex)
    
    asyncio.run(LanMessApp._handle_rotate(app, msg))
    
    c = db.get_contact("bob")
    assert c["ed_public_hex"] == new_ed_hex
    assert c["x25519_public_hex"] == new_x_hex
    assert c["session_established"] == 0
    assert c["chat_started"] == 0
    assert "rotated their keys" in app.notifications[-1]


def test_handle_rotate_rejects_bad_signature(db_path):
    db, old_sk = _setup(db_path)
    app = _FakeApp(db, old_sk)
    
    new_ed_hex = "aa" * 32
    new_x_hex = "bb" * 32
    
    msg = _make_rotate_msg(old_sk, "bob", new_ed_hex, new_x_hex)
    msg["signature"] = base64.b64encode(b"\x00" * 64).decode("ascii")
    
    asyncio.run(LanMessApp._handle_rotate(app, msg))
    
    c = db.get_contact("bob")
    assert c["ed_public_hex"] != new_ed_hex
    assert c["session_established"] == 1


def test_handle_presence_flushes_pending_rotate(db_path):
    db, old_sk = _setup(db_path)
    app = _FakeApp(db, old_sk)
    
    new_ed_hex = "cc" * 32
    new_x_hex = "dd" * 32
    
    payload = _make_rotate_msg(old_sk, "alice", new_ed_hex, new_x_hex)
    app._pending_rotates["bob"] = payload
    
    presence_msg = {
        "type": "PRESENCE",
        "from_name": "bob",
        "status": "online",
        "timestamp": int(time.time() * 1000)
    }
    
    with pytest.MonkeyPatch.context() as mp:
        async def mock_send(ip, port, payload, timeout=2.0):
            return {"type": "OK"}
            
        mp.setattr("lanmess_files.tui.send_request", mock_send)
        
        msg_data = CONTROL_SIG_PREFIX + json.dumps(
            {k:v for k,v in presence_msg.items() if k != "signature"}, 
            separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        presence_msg["signature"] = base64.b64encode(sign_bytes(old_sk, msg_data)).decode("ascii")
        
        asyncio.run(LanMessApp._handle_presence(app, presence_msg))
        
    assert "bob" not in app._pending_rotates