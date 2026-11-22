import asyncio
from unittest.mock import patch

from lanmess_files.crypto import compute_totp
from lanmess_files.database import Database

from .test_chat_handshake import (
    _Peer,
    _cleanup,
    _make_peer,
    _setup_two_peers,
)


for _name in [
    "block_contact",
    "unblock_contact",
]:
    setattr(_Peer, _name, getattr(
        __import__(
            "lanmess_files.tui", fromlist=["LanMessApp"]
        ).LanMessApp,
        _name,
    ))


def test_block_sets_state_and_table(db_path):
    alice, bob, fake_send = _setup_two_peers(db_path)

    async def run():
        with patch(
            "lanmess_files.tui.send_request", fake_send
        ):
            await alice.add_contact_by_ip(
                "127.0.0.1",
                bob.tcp_port,
                compute_totp(bob.totp_secret),
            )
            await bob.accept_contact("alice")

            await bob.block_contact("alice")
            assert bob.db.is_blocked("alice")
            contact = bob.db.get_contact("alice")
            assert contact.get("blocked") == 1

    try:
        asyncio.run(run())
    finally:
        _cleanup(db_path, alice, bob)


def test_blocked_peer_cannot_send(db_path):
    alice, bob, fake_send = _setup_two_peers(db_path)

    async def run():
        with patch(
            "lanmess_files.tui.send_request", fake_send
        ):
            await alice.add_contact_by_ip(
                "127.0.0.1",
                bob.tcp_port,
                compute_totp(bob.totp_secret),
            )
            await bob.accept_contact("alice")
            await alice.start_chat("bob")
            await bob.accept_chat("alice")

            await bob.block_contact("alice")
            ok = await alice.send_chat_message(
                "bob", "hi"
            )
            assert ok is False
            assert bob.db.get_messages("alice") == []

    try:
        asyncio.run(run())
    finally:
        _cleanup(db_path, alice, bob)


def test_unblock_clears_state(db_path):
    alice, bob, fake_send = _setup_two_peers(db_path)

    async def run():
        with patch(
            "lanmess_files.tui.send_request", fake_send
        ):
            await alice.add_contact_by_ip(
                "127.0.0.1",
                bob.tcp_port,
                compute_totp(bob.totp_secret),
            )
            await bob.accept_contact("alice")
            await bob.block_contact("alice")
            assert bob.db.is_blocked("alice")

            await bob.unblock_contact("alice")
            assert not bob.db.is_blocked("alice")
            contact = bob.db.get_contact("alice")
            assert contact.get("blocked") == 0

    try:
        asyncio.run(run())
    finally:
        _cleanup(db_path, alice, bob)


def test_blocked_survives_delete(db_path):
    alice, bob, fake_send = _setup_two_peers(db_path)

    async def run():
        with patch(
            "lanmess_files.tui.send_request", fake_send
        ):
            await alice.add_contact_by_ip(
                "127.0.0.1",
                bob.tcp_port,
                compute_totp(bob.totp_secret),
            )
            await bob.accept_contact("alice")
            await bob.block_contact("alice")
            bob.db.delete_contact("alice")
            assert bob.db.get_contact("alice") is None
            assert bob.db.is_blocked("alice")

    try:
        asyncio.run(run())
    finally:
        _cleanup(db_path, alice, bob)


def test_blocked_peer_cannot_readd(db_path):
    alice, bob, fake_send = _setup_two_peers(db_path)

    async def run():
        with patch(
            "lanmess_files.tui.send_request", fake_send
        ):
            await alice.add_contact_by_ip(
                "127.0.0.1",
                bob.tcp_port,
                compute_totp(bob.totp_secret),
            )
            await bob.accept_contact("alice")
            await bob.block_contact("alice")
            bob.db.delete_contact("alice")
            alice.db.delete_contact("bob")

            ok = await alice.add_contact_by_ip(
                "127.0.0.1",
                bob.tcp_port,
                compute_totp(bob.totp_secret),
            )
            assert ok is False
            assert alice.db.get_contact("bob") is None

    try:
        asyncio.run(run())
    finally:
        _cleanup(db_path, alice, bob)


def test_unblock_allows_readd(db_path):
    alice, bob, fake_send = _setup_two_peers(db_path)

    async def run():
        with patch(
            "lanmess_files.tui.send_request", fake_send
        ):
            await alice.add_contact_by_ip(
                "127.0.0.1",
                bob.tcp_port,
                compute_totp(bob.totp_secret),
            )
            await bob.accept_contact("alice")
            await bob.block_contact("alice")
            bob.db.delete_contact("alice")
            alice.db.delete_contact("bob")

            await bob.unblock_contact("alice")
            ok = await alice.add_contact_by_ip(
                "127.0.0.1",
                bob.tcp_port,
                compute_totp(bob.totp_secret),
            )
            assert ok is True
            assert alice.db.get_contact("bob") is not None

    try:
        asyncio.run(run())
    finally:
        _cleanup(db_path, alice, bob)


def test_blocked_persists_across_restart(db_path):
    alice, bob, fake_send = _setup_two_peers(db_path)
    master = bob.db.key

    async def run():
        with patch(
            "lanmess_files.tui.send_request", fake_send
        ):
            await alice.add_contact_by_ip(
                "127.0.0.1",
                bob.tcp_port,
                compute_totp(bob.totp_secret),
            )
            await bob.accept_contact("alice")
            await bob.block_contact("alice")

    try:
        asyncio.run(run())
        bob.db.close()
        bob_db2 = Database(db_path + ".b")
        assert bob_db2.set_master(master)
        assert bob_db2.is_blocked("alice")
        bob_db2.close()
    finally:
        _cleanup(db_path, alice, bob)


def test_legacy_blocked_cleanup(db_path):
    alice, bob, fake_send = _setup_two_peers(db_path)
    master = bob.db.key

    async def run():
        with patch(
            "lanmess_files.tui.send_request", fake_send
        ):
            await alice.add_contact_by_ip(
                "127.0.0.1",
                bob.tcp_port,
                compute_totp(bob.totp_secret),
            )
            await bob.accept_contact("alice")

    try:
        asyncio.run(run())
        bob.db.set_contact_state("alice", blocked=1)
        bob.db._set_meta("blocked_cleanup_v1", "")
        bob.db.close()
        bob_db2 = Database(db_path + ".b")
        assert bob_db2.set_master(master)
        contact = bob_db2.get_contact("alice")
        assert contact.get("blocked") == 0
        bob_db2.close()
    finally:
        _cleanup(db_path, alice, bob)