import asyncio
import os
from lanmess_files.database import Database
from lanmess_files.tui import LanMessApp


class _FakeApp:
    def __init__(self, db):
        self.db = db
        self.started_chats = []

    async def start_chat(self, name):
        self.started_chats.append(name)


def _setup(db_path):
    db = Database(db_path)
    db.create_identity(
        name="alice", master=os.urandom(32), group_key=os.urandom(32),
        ed_private_hex="00"*32, ed_public_hex="11"*32,
        totp_secret_hex="22"*20, tcp_port=50510,
        x25519_private_hex="33"*32, x25519_public_hex="44"*32
    )
    db.upsert_contact("bob", "10.0.0.5", 50520, "aa"*32, "bb"*32)
    return db


def test_auto_reconnect_triggers(db_path):
    async def _run():
        db = _setup(db_path)
        db.set_contact_state("bob", chat_started=1, session_established=0)
        app = _FakeApp(db)
        
        LanMessApp._check_auto_reconnect(app, "bob")
        await asyncio.sleep(0.01)
        assert "bob" in app.started_chats
    asyncio.run(_run())


def test_auto_reconnect_ignores_disconnected(db_path):
    async def _run():
        db = _setup(db_path)
        db.set_contact_state("bob", chat_started=0, session_established=0)
        app = _FakeApp(db)
        
        LanMessApp._check_auto_reconnect(app, "bob")
        await asyncio.sleep(0.01)
        assert len(app.started_chats) == 0
    asyncio.run(_run())