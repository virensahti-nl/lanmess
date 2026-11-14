import os
import pytest
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


def test_set_and_check_panic_pin(db_path):
    db = _setup(db_path)
    assert not db.check_panic_pin("panic123")
    db.set_panic_pin("panic123")
    assert db.check_panic_pin("panic123")
    assert not db.check_panic_pin("wrong")
    db.set_panic_pin("")
    assert not db.check_panic_pin("panic123")


def test_panic_wipe_resets_db(db_path):
    db = _setup(db_path)
    db.set_panic_pin("panic123")
    assert db.has_identity()
    db.reset_all()
    assert not db.has_identity()
    assert db.get_state() == "empty"