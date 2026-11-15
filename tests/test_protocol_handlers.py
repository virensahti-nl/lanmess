import asyncio
import base64
import hashlib
import hmac
import json
import os
import time

from lanmess_files.config import CONTROL_SIG_PREFIX
from lanmess_files.crypto import (
    aes_gcm_encrypt,
    chain_advance,
    chain_message_key,
    compute_totp,
    ed_public_to_bytes,
    generate_ed25519_private,
    pad_message,
    sign_bytes,
    x25519_generate,
)
from lanmess_files.database import Database
from lanmess_files.tui import LanMessApp


def _setup_db(db_path):
    db = Database(db_path)
    db.create_identity(
        name="alice",
        master=os.urandom(32),
        group_key=os.urandom(32),
        ed_private_hex="00" * 32,
        ed_public_hex="11" * 32,
        totp_secret_hex="22" * 20,
        tcp_port=50510,
        x25519_private_hex="33" * 32,
        x25519_public_hex="44" * 32,
    )
    db.set_notifications_enabled(False)
    return db


class _NoDiscovery:
    def find_by_name(self, name):
        return None


class _HandlerApp:
    def __init__(self, db):
        self.db = db
        self.user_name = "alice"
        self.ed_private = generate_ed25519_private()
        self.ed_public = self.ed_private.public_key()
        self.x25519_private = x25519_generate()
        self.x25519_public = self.x25519_private.public_key()
        self.tcp_port = 50510
        self.totp_secret = os.urandom(20)
        self.discovery = _NoDiscovery()
        self.screen = None
        self._last_heard = {}
        self._peer_offline = {}
        self._peer_typing = {}
        self._last_activity = {}
        self._add_attempts = {}
        self._msg_attempts = {}
        self._pending_rotates = {}
        self._presence_success = {}
        self._presence_fail = {}
        self._last_typing_sent = {}
        self._outbox = {}
        self._contact_locks = {}
        self.notifications = []

    def notify(self, msg, **kw):
        self.notifications.append(msg)

    def _touch_activity(self, name):
        pass

    def _refresh_main(self):
        pass

    def _refresh_visible_messages(self):
        pass

    def _audit(self, *a, **k):
        pass

    def _resolve_peer_address(self, contact):
        return ("127.0.0.1", 50510)

    def _is_currently_viewing(self, contact_name):
        return False

    async def _deferred_refresh(self, contact_name):
        return None


_HandlerApp._valid_name = LanMessApp._valid_name
_HandlerApp._valid_hex = LanMessApp._valid_hex
_HandlerApp._valid_timestamp = LanMessApp._valid_timestamp
_HandlerApp._check_signed = LanMessApp._check_signed
_HandlerApp._signed = LanMessApp._signed
_HandlerApp._prune_dict = LanMessApp._prune_dict
_HandlerApp._apply_peer_ip = LanMessApp._apply_peer_ip
_HandlerApp._touch_heard = LanMessApp._touch_heard
_HandlerApp._mark_offline = LanMessApp._mark_offline
_HandlerApp._verify_peer_sig_no_touch = (
    LanMessApp._verify_peer_sig_no_touch
)
_HandlerApp._verify_peer_sig = LanMessApp._verify_peer_sig
_HandlerApp._handle_message = LanMessApp._handle_message
_HandlerApp._handle_typing = LanMessApp._handle_typing
_HandlerApp._handle_rotate = LanMessApp._handle_rotate
_HandlerApp._handle_clear_request = (
    LanMessApp._handle_clear_request
)
_HandlerApp._handle_clear_accept = (
    LanMessApp._handle_clear_accept
)
_HandlerApp._handle_clear_reject = (
    LanMessApp._handle_clear_reject
)
_HandlerApp._handle_presence = LanMessApp._handle_presence
_HandlerApp._handle_add_request = (
    LanMessApp._handle_add_request
)


def _now_ms():
    return int(time.time() * 1000)


def _signed_control(fields, sk):
    body = dict(fields)
    data = CONTROL_SIG_PREFIX + json.dumps(
        body, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    sig = base64.b64encode(sign_bytes(sk, data)).decode()
    return {**body, "signature": sig}


def _register_bob(db, peer_sk, chain_hex=None):
    ed_hex = ed_public_to_bytes(peer_sk.public_key()).hex()
    db.upsert_contact(
        "bob", "10.0.0.5", 50520, ed_hex, "bb" * 32
    )
    db.set_contact_state(
        "bob",
        chat_started=1,
        session_established=1,
        pending=0,
        send_chain_key_hex="00" * 32,
        recv_chain_key_hex=chain_hex or "11" * 32,
        send_counter=0,
        recv_counter=0,
    )


def _build_message_frame(
    peer_sk,
    from_name,
    counter,
    recv_chain,
    text="hello",
    reply_to=0,
    react_to=0,
):
    chain_at = recv_chain
    for _ in range(counter - 1):
        chain_at = chain_advance(chain_at)
    msg_key = chain_message_key(chain_at)
    nonce = os.urandom(12)
    aad = f"{from_name}:{counter}".encode("utf-8")
    padded = pad_message(text.encode("utf-8"))
    ct = aes_gcm_encrypt(msg_key, padded, nonce, aad)
    signed_data = (
        from_name.encode("utf-8")
        + counter.to_bytes(8, "big")
        + nonce
        + ct
        + reply_to.to_bytes(8, "big")
        + react_to.to_bytes(8, "big")
    )
    sig = sign_bytes(peer_sk, signed_data)
    frame = {
        "type": "MESSAGE",
        "from_name": from_name,
        "counter": counter,
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ct).decode(),
        "signature": base64.b64encode(sig).decode(),
    }
    if reply_to:
        frame["reply_to"] = reply_to
    if react_to:
        frame["react_to"] = react_to
    return frame


def test_handle_message_happy_path(db_path):
    db = _setup_db(db_path)
    peer_sk = generate_ed25519_private()
    recv_chain = bytes.fromhex("11" * 32)
    _register_bob(db, peer_sk, chain_hex=recv_chain.hex())
    app = _HandlerApp(db)
    frame = _build_message_frame(
        peer_sk, "bob", 1, recv_chain, text="hi"
    )
    resp = asyncio.run(app._handle_message(frame))
    assert resp == {"type": "OK"}
    msgs = db.get_messages("bob")
    assert len(msgs) == 1
    assert msgs[0]["content"] == "hi"


def test_handle_message_with_reply(db_path):
    db = _setup_db(db_path)
    peer_sk = generate_ed25519_private()
    recv_chain = bytes.fromhex("11" * 32)
    _register_bob(db, peer_sk, chain_hex=recv_chain.hex())
    app = _HandlerApp(db)
    frame = _build_message_frame(
        peer_sk, "bob", 1, recv_chain,
        text="reply text", reply_to=7,
    )
    resp = asyncio.run(app._handle_message(frame))
    assert resp == {"type": "OK"}
    msgs = db.get_messages("bob")
    assert msgs[0]["reply_to"] == 7


def test_handle_message_with_react(db_path):
    db = _setup_db(db_path)
    peer_sk = generate_ed25519_private()
    recv_chain = bytes.fromhex("11" * 32)
    _register_bob(db, peer_sk, chain_hex=recv_chain.hex())
    app = _HandlerApp(db)
    frame = _build_message_frame(
        peer_sk, "bob", 1, recv_chain,
        text="👍", react_to=3,
    )
    resp = asyncio.run(app._handle_message(frame))
    assert resp == {"type": "OK"}
    msgs = db.get_messages("bob")
    assert msgs[0]["react_to"] == 3


def test_handle_message_rejects_tampered_reply(db_path):
    db = _setup_db(db_path)
    peer_sk = generate_ed25519_private()
    recv_chain = bytes.fromhex("11" * 32)
    _register_bob(db, peer_sk, chain_hex=recv_chain.hex())
    app = _HandlerApp(db)
    frame = _build_message_frame(
        peer_sk, "bob", 1, recv_chain,
        text="hi", reply_to=5,
    )
    frame["reply_to"] = 6
    resp = asyncio.run(app._handle_message(frame))
    assert resp.get("reason") == "sig_fail"
    assert db.get_messages("bob") == []


def test_handle_message_rejects_tampered_react(db_path):
    db = _setup_db(db_path)
    peer_sk = generate_ed25519_private()
    recv_chain = bytes.fromhex("11" * 32)
    _register_bob(db, peer_sk, chain_hex=recv_chain.hex())
    app = _HandlerApp(db)
    frame = _build_message_frame(
        peer_sk, "bob", 1, recv_chain,
        text="👍", react_to=3,
    )
    frame["react_to"] = 4
    resp = asyncio.run(app._handle_message(frame))
    assert resp.get("reason") == "sig_fail"
    assert db.get_messages("bob") == []


def test_handle_message_rejects_replay(db_path):
    db = _setup_db(db_path)
    peer_sk = generate_ed25519_private()
    recv_chain = bytes.fromhex("11" * 32)
    _register_bob(db, peer_sk, chain_hex=recv_chain.hex())
    app = _HandlerApp(db)
    frame = _build_message_frame(
        peer_sk, "bob", 1, recv_chain, text="once"
    )
    assert asyncio.run(
        app._handle_message(frame)
    ) == {"type": "OK"}
    resp = asyncio.run(app._handle_message(frame))
    assert resp.get("reason") == "replay"


def test_handle_message_sequence(db_path):
    db = _setup_db(db_path)
    peer_sk = generate_ed25519_private()
    recv_chain = bytes.fromhex("11" * 32)
    _register_bob(db, peer_sk, chain_hex=recv_chain.hex())
    app = _HandlerApp(db)
    for i in range(1, 6):
        frame = _build_message_frame(
            peer_sk, "bob", i, recv_chain, text=f"msg{i}"
        )
        assert asyncio.run(
            app._handle_message(frame)
        ) == {"type": "OK"}
    msgs = db.get_messages("bob")
    assert [m["content"] for m in msgs] == [
        "msg1", "msg2", "msg3", "msg4", "msg5"
    ]


def test_handle_message_bad_sig_does_not_block(db_path):
    db = _setup_db(db_path)
    peer_sk = generate_ed25519_private()
    recv_chain = bytes.fromhex("11" * 32)
    _register_bob(db, peer_sk, chain_hex=recv_chain.hex())
    app = _HandlerApp(db)
    frame = _build_message_frame(
        peer_sk, "bob", 1, recv_chain, text="hi"
    )
    frame["signature"] = base64.b64encode(
        b"\x00" * 64
    ).decode()
    resp = asyncio.run(app._handle_message(frame))
    assert resp.get("reason") == "sig_fail"
    contact = db.get_contact("bob")
    assert contact.get("blocked") == 0
    assert db.get_messages("bob") == []


def test_handle_message_bad_decryption_does_not_block(db_path):
    db = _setup_db(db_path)
    peer_sk = generate_ed25519_private()
    recv_chain = bytes.fromhex("11" * 32)
    _register_bob(db, peer_sk, chain_hex=recv_chain.hex())
    app = _HandlerApp(db)
    msg_key = chain_message_key(recv_chain)
    nonce = os.urandom(12)
    padded = pad_message(b"hi")
    wrong_aad = b"bob:999"
    ct = aes_gcm_encrypt(msg_key, padded, nonce, wrong_aad)
    counter = 1
    reply_to = 0
    react_to = 0
    signed_data = (
        b"bob"
        + counter.to_bytes(8, "big")
        + nonce
        + ct
        + reply_to.to_bytes(8, "big")
        + react_to.to_bytes(8, "big")
    )
    sig = sign_bytes(peer_sk, signed_data)
    frame = {
        "type": "MESSAGE",
        "from_name": "bob",
        "counter": counter,
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ct).decode(),
        "signature": base64.b64encode(sig).decode(),
    }
    resp = asyncio.run(app._handle_message(frame))
    assert resp.get("reason") == "dec_fail"
    contact = db.get_contact("bob")
    assert contact.get("blocked") == 0
    assert db.get_messages("bob") == []


def test_handle_message_requires_session(db_path):
    db = _setup_db(db_path)
    peer_sk = generate_ed25519_private()
    _register_bob(db, peer_sk)
    db.set_contact_state("bob", session_established=0)
    app = _HandlerApp(db)
    frame = _build_message_frame(
        peer_sk, "bob", 1, bytes.fromhex("11" * 32)
    )
    resp = asyncio.run(app._handle_message(frame))
    assert resp.get("reason") == "no_session"


def test_handle_message_requires_chat_started(db_path):
    db = _setup_db(db_path)
    peer_sk = generate_ed25519_private()
    _register_bob(db, peer_sk)
    db.set_contact_state("bob", chat_started=0)
    app = _HandlerApp(db)
    frame = _build_message_frame(
        peer_sk, "bob", 1, bytes.fromhex("11" * 32)
    )
    resp = asyncio.run(app._handle_message(frame))
    assert resp.get("reason") == "no_chat"


def test_handle_typing_valid(db_path):
    db = _setup_db(db_path)
    peer_sk = generate_ed25519_private()
    _register_bob(db, peer_sk)
    app = _HandlerApp(db)
    msg = _signed_control(
        {
            "type": "TYPING",
            "from_name": "bob",
            "timestamp": _now_ms(),
        },
        peer_sk,
    )
    resp = asyncio.run(app._handle_typing(msg))
    assert resp == {"type": "OK"}
    assert "bob" in app._peer_typing


def test_handle_typing_bad_sig(db_path):
    db = _setup_db(db_path)
    peer_sk = generate_ed25519_private()
    _register_bob(db, peer_sk)
    app = _HandlerApp(db)
    msg = _signed_control(
        {
            "type": "TYPING",
            "from_name": "bob",
            "timestamp": _now_ms(),
        },
        peer_sk,
    )
    msg["signature"] = base64.b64encode(
        b"\x00" * 64
    ).decode()
    resp = asyncio.run(app._handle_typing(msg))
    assert resp == {"type": "OK"}
    assert "bob" not in app._peer_typing


def test_handle_rotate_valid(db_path):
    db = _setup_db(db_path)
    peer_sk = generate_ed25519_private()
    _register_bob(db, peer_sk)
    app = _HandlerApp(db)
    new_ed = "aa" * 32
    new_x = "bb" * 32
    msg = _signed_control(
        {
            "type": "ROTATE",
            "from_name": "bob",
            "new_ed_pub": new_ed,
            "new_x25519_pub": new_x,
            "timestamp": _now_ms(),
        },
        peer_sk,
    )
    resp = asyncio.run(app._handle_rotate(msg))
    assert resp == {"type": "OK"}
    contact = db.get_contact("bob")
    assert contact["ed_public_hex"] == new_ed
    assert contact["x25519_public_hex"] == new_x


def test_handle_clear_request_sets_pending(db_path):
    db = _setup_db(db_path)
    peer_sk = generate_ed25519_private()
    _register_bob(db, peer_sk)
    app = _HandlerApp(db)
    msg = _signed_control(
        {
            "type": "CLEAR_REQUEST",
            "from_name": "bob",
            "timestamp": _now_ms(),
        },
        peer_sk,
    )
    resp = asyncio.run(app._handle_clear_request(msg))
    assert resp.get("type") == "CLEAR_PENDING"
    contact = db.get_contact("bob")
    assert contact.get("clear_pending") == 1


def test_handle_clear_accept_clears_messages(db_path):
    db = _setup_db(db_path)
    peer_sk = generate_ed25519_private()
    _register_bob(db, peer_sk)
    db.add_message("bob", "in", "hello")
    app = _HandlerApp(db)
    msg = _signed_control(
        {
            "type": "CLEAR_ACCEPT",
            "from_name": "bob",
            "timestamp": _now_ms(),
        },
        peer_sk,
    )
    resp = asyncio.run(app._handle_clear_accept(msg))
    assert resp == {"type": "OK"}
    assert db.get_messages("bob") == []


def test_handle_clear_reject_clears_pending(db_path):
    db = _setup_db(db_path)
    peer_sk = generate_ed25519_private()
    _register_bob(db, peer_sk)
    db.set_contact_state("bob", clear_pending=1)
    app = _HandlerApp(db)
    msg = _signed_control(
        {
            "type": "CLEAR_REJECT",
            "from_name": "bob",
            "timestamp": _now_ms(),
        },
        peer_sk,
    )
    resp = asyncio.run(app._handle_clear_reject(msg))
    assert resp == {"type": "OK"}
    contact = db.get_contact("bob")
    assert contact.get("clear_pending") == 0


def test_handle_presence_online_touches(db_path):
    db = _setup_db(db_path)
    peer_sk = generate_ed25519_private()
    _register_bob(db, peer_sk)
    app = _HandlerApp(db)
    msg = _signed_control(
        {
            "type": "PRESENCE",
            "from_name": "bob",
            "status": "online",
            "timestamp": _now_ms(),
        },
        peer_sk,
    )
    resp = asyncio.run(app._handle_presence(msg))
    assert resp.get("type") == "OK"
    assert "bob" in app._last_heard


def test_handle_presence_offline_marks_offline(db_path):
    db = _setup_db(db_path)
    peer_sk = generate_ed25519_private()
    _register_bob(db, peer_sk)
    app = _HandlerApp(db)
    msg = _signed_control(
        {
            "type": "PRESENCE",
            "from_name": "bob",
            "status": "offline",
            "timestamp": _now_ms(),
        },
        peer_sk,
    )
    resp = asyncio.run(app._handle_presence(msg))
    assert resp == {"type": "OK"}
    assert "bob" in app._peer_offline


def test_handle_add_request_pending_on_new_contact(db_path):
    db = _setup_db(db_path)
    app = _HandlerApp(db)
    peer_sk = generate_ed25519_private()
    peer_ed = ed_public_to_bytes(
        peer_sk.public_key()
    ).hex()
    peer_x = "bb" * 32
    code = compute_totp(app.totp_secret)
    challenge = os.urandom(32)
    proof = hmac.new(
        code.encode("utf-8"),
        b"REQ" + b"bob" + challenge,
        hashlib.sha256,
    ).digest()
    fields = {
        "type": "ADD_REQUEST",
        "from_name": "bob",
        "from_ed_pub": peer_ed,
        "from_x25519_pub": peer_x,
        "from_port": 50520,
        "challenge": base64.b64encode(challenge).decode(),
        "proof": proof.hex(),
        "timestamp": _now_ms(),
    }
    msg = _signed_control(fields, peer_sk)
    resp = asyncio.run(app._handle_add_request(msg))
    assert resp.get("type") == "ADD_PENDING"
    contact = db.get_contact("bob")
    assert contact is not None
    assert contact.get("pending") == 2


def test_handle_add_request_rejects_self(db_path):
    db = _setup_db(db_path)
    app = _HandlerApp(db)
    peer_sk = generate_ed25519_private()
    fields = {
        "type": "ADD_REQUEST",
        "from_name": "alice",
        "from_ed_pub": ed_public_to_bytes(
            peer_sk.public_key()
        ).hex(),
        "from_x25519_pub": "bb" * 32,
        "from_port": 50520,
        "challenge": base64.b64encode(
            os.urandom(32)
        ).decode(),
        "proof": "00" * 32,
        "timestamp": _now_ms(),
    }
    msg = _signed_control(fields, peer_sk)
    resp = asyncio.run(app._handle_add_request(msg))
    assert resp.get("reason") == "self"


def test_handle_add_request_rejects_invalid_code(db_path):
    db = _setup_db(db_path)
    app = _HandlerApp(db)
    peer_sk = generate_ed25519_private()
    peer_ed = ed_public_to_bytes(
        peer_sk.public_key()
    ).hex()
    challenge = os.urandom(32)
    proof = hmac.new(
        b"wrongcode",
        b"REQ" + b"bob" + challenge,
        hashlib.sha256,
    ).digest()
    fields = {
        "type": "ADD_REQUEST",
        "from_name": "bob",
        "from_ed_pub": peer_ed,
        "from_x25519_pub": "bb" * 32,
        "from_port": 50520,
        "challenge": base64.b64encode(challenge).decode(),
        "proof": proof.hex(),
        "timestamp": _now_ms(),
    }
    msg = _signed_control(fields, peer_sk)
    resp = asyncio.run(app._handle_add_request(msg))
    assert resp.get("reason") == "invalid_code"
    assert db.get_contact("bob") is None