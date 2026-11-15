import os

import pytest
from lanmess_files.config import PANIC_SALT_BYTES
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


def test_panic_pin_stores_salt(db_path):
    db = _setup(db_path)
    db.set_panic_pin("panic123")
    row = db._security_row()
    assert row["panic_pin_salt"] is not None
    assert len(bytes(row["panic_pin_salt"])) == PANIC_SALT_BYTES


def test_panic_pin_hash_is_32_bytes(db_path):
    db = _setup(db_path)
    db.set_panic_pin("panic123")
    row = db._security_row()
    assert row["panic_pin_hash"] is not None
    assert len(row["panic_pin_hash"]) == 64
    assert all(
        c in "0123456789abcdef"
        for c in row["panic_pin_hash"]
    )


def test_panic_pin_uses_unique_salt_per_set(db_path):
    db = _setup(db_path)
    db.set_panic_pin("panic123")
    first_salt = bytes(db._security_row()["panic_pin_salt"])
    db.set_panic_pin("panic123")
    second_salt = bytes(db._security_row()["panic_pin_salt"])
    assert first_salt != second_salt


def test_panic_pin_clear_resets_hash_and_salt(db_path):
    db = _setup(db_path)
    db.set_panic_pin("panic123")
    db.set_panic_pin("")
    row = db._security_row()
    assert row["panic_pin_hash"] is None
    assert row["panic_pin_salt"] is None


def test_panic_pin_empty_pin_returns_false(db_path):
    db = _setup(db_path)
    assert not db.check_panic_pin("")
    db.set_panic_pin("panic123")
    assert not db.check_panic_pin("")


def test_panic_pin_wrong_password_rejected(db_path):
    db = _setup(db_path)
    db.set_panic_pin("correct-panic-password")
    assert db.check_panic_pin("correct-panic-password")
    for wrong in (
        "wrong",
        "Correct-Panic-Password",
        "correct-panic-passwor",
        "correct-panic-password ",
    ):
        assert not db.check_panic_pin(wrong)


def test_panic_wipe_resets_db(db_path):
    db = _setup(db_path)
    db.set_panic_pin("panic123")
    assert db.has_identity()
    db.reset_all()
    assert not db.has_identity()
    assert db.get_state() == "empty"


def test_panic_pin_survives_reopen(db_path):
    db = _setup(db_path)
    db.set_panic_pin("panic123")
    master = db.key
    db.close()
    db2 = Database(db_path)
    assert db2.set_master(master)
    assert db2.check_panic_pin("panic123")
    assert not db2.check_panic_pin("wrong")