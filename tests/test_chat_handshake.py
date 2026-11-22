import asyncio
import time
from unittest.mock import patch

from lanmess_files.config import CONTROL_SIG_PREFIX
from lanmess_files.crypto import (
    compute_totp,
    ed_private_to_bytes,
    ed_public_to_bytes,
    generate_ed25519_private,
    generate_totp_secret,
    x25519_generate,
    x25519_private_to_bytes,
    x25519_public_to_bytes,
)
from lanmess_files.database import Database
from lanmess_files.tui import LanMessApp


class _NoDiscovery:
    def find_by_name(self, name):
        return None

    def find_by_code_tag(self, tag, exclude_name=None):
        return None, None


class _Peer:
    def __init__(self, db, keys):
        self.db = db
        self.user_name = keys["name"]
        self.ed_private = keys["ed_private"]
        self.ed_public = keys["ed_public"]
        self.x25519_private = keys["x25519_private"]
        self.x25519_public = keys["x25519_public"]
        self.totp_secret = keys["totp_secret"]
        self.tcp_port = keys["tcp_port"]
        self.group_key = keys["group_key"]
        self.discovery = _NoDiscovery()
        self._last_heard = {}
        self._peer_offline = {}
        self._peer_typing = {}
        self._last_activity = {}
        self._add_attempts = {}
        self._name_attempts = {}
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

    def _audit(self, *a, **k):
        pass

    def _refresh_main(self, *a, **k):
        pass

    def _refresh_visible_messages(self, *a, **k):
        pass

    def _touch_activity(self, name):
        self._last_activity[name] = time.time()

    def _apply_peer_ip(self, msg, name):
        pass

    def _resolve_peer_address(self, contact):
        return (
            contact.get("ip") or "127.0.0.1",
            contact.get("port") or self.tcp_port,
        )

    def _is_currently_viewing(self, name):
        return False

    def _prune_dict(self, d, cap):
        if len(d) > cap:
            d.clear()

    async def _deferred_refresh(self, name):
        pass

    async def _send_presence_now(self, name):
        pass

    def _get_main_screen(self):
        return None


for _name in [
    "_valid_name", "_valid_hex", "_valid_timestamp",
    "_signed", "_check_signed",
    "_get_contact_lock",
    "_touch_heard", "_mark_offline",
    "_verify_peer_sig", "_verify_peer_sig_no_touch",
    "handle_incoming",
    "_handle_add_request", "_handle_add_accept", "_handle_add_reject",
    "_handle_chat_start", "_handle_chat_accept",
    "_handle_chat_reject", "_handle_chat_stop",
    "_handle_clear_request", "_handle_clear_accept",
    "_handle_clear_reject", "_handle_presence",
    "_handle_typing", "_handle_message", "_handle_rotate",
    "accept_contact", "reject_contact",
    "accept_chat", "reject_chat",
    "start_chat", "stop_chat",
    "send_chat_message",
    "_build_add_request_payload",
    "_process_add_response",
    "add_contact_by_ip",
]:
    setattr(_Peer, _name, getattr(LanMessApp, _name))


def _make_peer(name, db_path, tcp_port):
    db = Database(db_path)
    master = __import__("os").urandom(32)
    group_key = __import__("os").urandom(32)
    sk_ed = generate_ed25519_private()
    pk_ed = sk_ed.public_key()
    sk_x = x25519_generate()
    pk_x = sk_x.public_key()
    totp = generate_totp_secret()
    db.create_identity(
        name=name,
        master=master,
        group_key=group_key,
        ed_private_hex=ed_private_to_bytes(sk_ed).hex(),
        ed_public_hex=ed_public_to_bytes(pk_ed).hex(),
        totp_secret_hex=totp.hex(),
        tcp_port=tcp_port,
        x25519_private_hex=x25519_private_to_bytes(sk_x).hex(),
        x25519_public_hex=x25519_public_to_bytes(pk_x).hex(),
    )
    return db, {
        "name": name,
        "group_key": group_key,
        "ed_private": sk_ed,
        "ed_public": pk_ed,
        "x25519_private": sk_x,
        "x25519_public": pk_x,
        "totp_secret": totp,
        "tcp_port": tcp_port,
        "master": master,
    }


def _setup_two_peers(db_path):
    alice_db, alice_keys = _make_peer(
        "alice", db_path + ".a", 50510
    )
    bob_db, bob_keys = _make_peer(
        "bob", db_path + ".b", 50520
    )
    alice = _Peer(alice_db, alice_keys)
    bob = _Peer(bob_db, bob_keys)
    routing = {
        ("127.0.0.1", 50510): alice,
        ("127.0.0.1", 50520): bob,
    }

    async def fake_send(ip, port, payload, timeout=2.0):
        target = routing.get((ip, port))
        if target is None:
            return None
        return await target.handle_incoming(payload)

    return alice, bob, fake_send


def _cleanup(db_path, alice, bob):
    try:
        alice.db.close()
    except Exception:
        pass
    try:
        bob.db.close()
    except Exception:
        pass
    import os
    for suffix in ("a", "b"):
        for ext in ("", "-wal", "-shm", "-journal"):
            try:
                os.unlink(db_path + "." + suffix + ext)
            except Exception:
                pass



def test_full_chat_handshake(db_path):
    alice, bob, fake_send = _setup_two_peers(db_path)

    async def run():
        with patch(
            "lanmess_files.tui.send_request", fake_send
        ):
            ok = await alice.add_contact_by_ip(
                "127.0.0.1",
                bob.tcp_port,
                compute_totp(bob.totp_secret),
            )
            assert ok

            alice_contact = alice.db.get_contact("bob")
            assert alice_contact is not None
            assert alice_contact.get("pending") == 1

            await bob.accept_contact("alice")

            bob_contact = bob.db.get_contact("alice")
            assert bob_contact.get("pending") == 0

            alice_contact = alice.db.get_contact("bob")
            assert alice_contact.get("pending") == 0

            await alice.start_chat("bob")

            alice_contact = alice.db.get_contact("bob")
            assert alice_contact.get("session_local_eph_sk_hex") != ""

            await bob.accept_chat("alice")

            alice_contact = alice.db.get_contact("bob")
            bob_contact = bob.db.get_contact("alice")

            assert alice_contact.get("session_established") == 1
            assert bob_contact.get("session_established") == 1

            alice_send = alice_contact["send_chain_key_hex"]
            alice_recv = alice_contact["recv_chain_key_hex"]
            bob_send = bob_contact["send_chain_key_hex"]
            bob_recv = bob_contact["recv_chain_key_hex"]

            assert alice_send == bob_recv
            assert alice_recv == bob_send

            ok = await alice.send_chat_message(
                "bob", "hello bob"
            )
            assert ok

            bob_msgs = bob.db.get_messages("alice")

            assert len(bob_msgs) == 1
            assert bob_msgs[0]["content"] == "hello bob"
            assert bob_msgs[0]["direction"] == "in"

            ok = await bob.send_chat_message(
                "alice", "hello alice"
            )
            assert ok

            alice_msgs = alice.db.get_messages("bob")

            assert len(alice_msgs) == 2

            assert alice_msgs[0]["content"] == "hello bob"
            assert alice_msgs[0]["direction"] == "out"

            assert alice_msgs[1]["content"] == "hello alice"
            assert alice_msgs[1]["direction"] == "in"

            await alice.stop_chat("bob")

            alice_contact = alice.db.get_contact("bob")
            bob_contact = bob.db.get_contact("alice")

            assert alice_contact.get("session_established") == 0
            assert bob_contact.get("session_established") == 0

    try:
        asyncio.run(run())
    finally:
        _cleanup(db_path, alice, bob)


def test_chat_reject_cleans_local_ephemeral(db_path):
    alice, bob, fake_send = _setup_two_peers(db_path)

    async def run():
        with patch(
            "lanmess_files.tui.send_request", fake_send
        ):
            ok = await alice.add_contact_by_ip(
                "127.0.0.1",
                bob.tcp_port,
                compute_totp(bob.totp_secret),
            )
            assert ok
            await bob.accept_contact("alice")

            await alice.start_chat("bob")
            alice_contact = alice.db.get_contact("bob")
            assert (
                alice_contact.get("session_local_eph_sk_hex")
                != ""
            )

            await bob.reject_chat("alice")
            alice_contact = alice.db.get_contact("bob")
            assert (
                alice_contact.get("session_local_eph_sk_hex")
                == ""
            )
            assert (
                alice_contact.get("session_established") == 0
            )

    try:
        asyncio.run(run())
    finally:
        _cleanup(db_path, alice, bob)


def test_chat_stop_clears_outbox(db_path):
    alice, bob, fake_send = _setup_two_peers(db_path)

    async def run():
        with patch(
            "lanmess_files.tui.send_request", fake_send
        ):
            ok = await alice.add_contact_by_ip(
                "127.0.0.1",
                bob.tcp_port,
                compute_totp(bob.totp_secret),
            )
            assert ok
            await bob.accept_contact("alice")
            await alice.start_chat("bob")
            await bob.accept_chat("alice")

            alice._outbox["bob"] = [
                {"text": "x", "reply_to": 0, "react_to": 0}
            ]

            await bob.stop_chat("alice")
            assert "bob" not in alice._outbox

    try:
        asyncio.run(run())
    finally:
        _cleanup(db_path, alice, bob)