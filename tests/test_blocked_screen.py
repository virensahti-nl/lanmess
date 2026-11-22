import asyncio
import os

from textual.app import App
from textual.widgets import Button

from lanmess_files.database import Database
from lanmess_files.tui.screens.blocked import BlockedScreen


def _identity(db):
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


def _setup_db_with_blocked(db_path, name):
    db = Database(db_path)
    _identity(db)
    db.add_blocked(name, "aa" * 32)
    return db


class _TestApp(App):
    def __init__(self, db):
        super().__init__()
        self.db = db
        self.unblocked = []

    async def unblock_contact(self, name):
        self.unblocked.append(name)
        self.db.remove_blocked(name)


def test_blocked_screen_opens_with_spaced_name(db_path):
    db = _setup_db_with_blocked(db_path, "Bob Smith")
    try:
        app = _TestApp(db)

        async def run():
            async with app.run_test() as pilot:
                await app.push_screen(BlockedScreen())
                await pilot.pause()
                assert isinstance(app.screen, BlockedScreen)
                buttons = [
                    b for b in app.screen.query(Button)
                    if b.id != "blocked-close"
                ]
                assert len(buttons) == 1
                assert buttons[0]._blocked_name == "Bob Smith"

        asyncio.run(run())
    finally:
        db.close()


def test_blocked_screen_opens_with_special_chars(db_path):
    db = _setup_db_with_blocked(db_path, "bob@example")
    try:
        app = _TestApp(db)

        async def run():
            async with app.run_test() as pilot:
                await app.push_screen(BlockedScreen())
                await pilot.pause()
                buttons = [
                    b for b in app.screen.query(Button)
                    if b.id != "blocked-close"
                ]
                assert len(buttons) == 1
                assert buttons[0]._blocked_name == "bob@example"

        asyncio.run(run())
    finally:
        db.close()


def test_blocked_screen_empty_shows_hint(db_path):
    db = Database(db_path)
    _identity(db)
    try:
        app = _TestApp(db)

        async def run():
            async with app.run_test() as pilot:
                await app.push_screen(BlockedScreen())
                await pilot.pause()
                buttons = [
                    b for b in app.screen.query(Button)
                    if b.id != "blocked-close"
                ]
                assert len(buttons) == 0

        asyncio.run(run())
    finally:
        db.close()


def test_blocked_screen_unblock_click(db_path):
    db = _setup_db_with_blocked(db_path, "Bob Smith")
    try:
        app = _TestApp(db)

        async def run():
            async with app.run_test() as pilot:
                await app.push_screen(BlockedScreen())
                await pilot.pause()
                buttons = [
                    b for b in app.screen.query(Button)
                    if b.id != "blocked-close"
                ]
                assert len(buttons) == 1
                await pilot.click(buttons[0])
                await pilot.pause()
                assert "Bob Smith" in app.unblocked
                assert not db.is_blocked("Bob Smith")

        asyncio.run(run())
    finally:
        db.close()