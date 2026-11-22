import os

from lanmess_files.crypto import (
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


def _make_db(db_path, pin):
    db = Database(db_path)
    master = os.urandom(32)
    group_key = os.urandom(32)
    sk_ed = generate_ed25519_private()
    sk_x = x25519_generate()
    totp = generate_totp_secret()
    db.create_identity(
        name="alice",
        master=master,
        group_key=group_key,
        ed_private_hex=ed_private_to_bytes(sk_ed).hex(),
        ed_public_hex=ed_public_to_bytes(
            sk_ed.public_key()
        ).hex(),
        totp_secret_hex=totp.hex(),
        tcp_port=50510,
        x25519_private_hex=x25519_private_to_bytes(sk_x).hex(),
        x25519_public_hex=x25519_public_to_bytes(
            sk_x.public_key()
        ).hex(),
    )
    db.setup_vault(master, pin)
    return db, master


def test_db_change_pin_roundtrip(db_path):
    old_pin = "OldPin12345!"
    new_pin = "NewPin98765!"
    db, master = _make_db(db_path, old_pin)
    assert db.unlock_vault(old_pin) == master
    ok = db.setup_vault(master, new_pin)
    assert ok
    db.close()
    db2 = Database(db_path)
    assert db2.unlock_vault(old_pin) is None
    assert db2.unlock_vault(new_pin) == master
    db2.close()


def test_app_change_pin_success(db_path):
    old_pin = "OldPin12345!"
    new_pin = "NewPin98765!"
    db, master = _make_db(db_path, old_pin)

    class _App:
        def __init__(self):
            self.db = db
            self.notifications = []

        def notify(self, msg, **kw):
            self.notifications.append(msg)

        def _audit(self, *a, **k):
            pass

    _App.change_pin = LanMessApp.change_pin
    app = _App()

    import asyncio
    ok = asyncio.run(
        LanMessApp.change_pin(app, old_pin, new_pin)
    )
    assert ok
    db.close()
    db2 = Database(db_path)
    assert db2.unlock_vault(old_pin) is None
    assert db2.unlock_vault(new_pin) == master
    db2.close()


def test_app_change_pin_wrong_old(db_path):
    old_pin = "OldPin12345!"
    db, master = _make_db(db_path, old_pin)

    class _App:
        def __init__(self):
            self.db = db
            self.notifications = []

        def notify(self, msg, **kw):
            self.notifications.append(msg)

        def _audit(self, *a, **k):
            pass

    _App.change_pin = LanMessApp.change_pin
    app = _App()

    import asyncio
    ok = asyncio.run(
        LanMessApp.change_pin(
            app, "WrongPin1234!", "NewPin98765!"
        )
    )
    assert not ok
    assert db.unlock_vault(old_pin) == master
    db.close()


def test_app_change_pin_weak_new(db_path):
    old_pin = "OldPin12345!"
    db, _master = _make_db(db_path, old_pin)

    class _App:
        def __init__(self):
            self.db = db
            self.notifications = []

        def notify(self, msg, **kw):
            self.notifications.append(msg)

        def _audit(self, *a, **k):
            pass

    _App.change_pin = LanMessApp.change_pin
    app = _App()

    import asyncio
    ok = asyncio.run(
        LanMessApp.change_pin(app, old_pin, "weak")
    )
    assert not ok
    db.close()