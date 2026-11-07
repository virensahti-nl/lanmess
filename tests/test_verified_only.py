import os

from lanmess_files.database import Database


def _setup(db_path):
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
    return db


def test_verified_only_default_off(db_path):
    db = _setup(db_path)
    assert db.get_verified_only() is False


def test_verified_only_toggle(db_path):
    db = _setup(db_path)
    db.set_verified_only(True)
    assert db.get_verified_only() is True
    db.set_verified_only(False)
    assert db.get_verified_only() is False


def test_verified_only_persists(db_path):
    db = _setup(db_path)
    db.set_verified_only(True)
    master = db.key
    db.close()
    db2 = Database(db_path)
    db2.set_master(master)
    assert db2.get_verified_only() is True


def test_notifications_default_on(db_path):
    db = _setup(db_path)
    assert db.get_notifications_enabled() is True


def test_notifications_toggle(db_path):
    db = _setup(db_path)
    db.set_notifications_enabled(False)
    assert db.get_notifications_enabled() is False


def test_presence_default_on(db_path):
    db = _setup(db_path)
    assert db.get_presence_enabled() is True


def test_presence_toggle(db_path):
    db = _setup(db_path)
    db.set_presence_enabled(False)
    assert db.get_presence_enabled() is False