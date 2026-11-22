import base64
import os

import pytest

from lanmess_files.config import (
    PANIC_MARKER,
    PANIC_MARKER_BYTES,
    PANIC_PREFIX_V10,
    PANIC_SALT_BYTES,
)
from lanmess_files.crypto import (
    aes_gcm_encrypt,
    derive_pin_key,
)
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


def test_panic_pin_stored_as_ciphertext(db_path):
    db = _setup(db_path)
    db.set_panic_pin("panic123")
    row = db._security_row()
    stored = row["panic_pin_hash"]
    assert isinstance(stored, str)
    assert stored.startswith(PANIC_PREFIX_V10)
    payload = stored[len(PANIC_PREFIX_V10):]
    raw = base64.b64decode(payload)
    assert len(raw) == 12 + PANIC_MARKER_BYTES + 16


def test_panic_pin_not_plaintext_argon2id(db_path):
    db = _setup(db_path)
    db.set_panic_pin("panic123")
    row = db._security_row()
    stored = row["panic_pin_hash"]
    salt = bytes(row["panic_pin_salt"])
    argon2_hex = derive_pin_key("panic123", salt).hex()
    assert stored != argon2_hex
    assert argon2_hex not in stored
    assert "panic123" not in stored


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


def test_panic_pin_legacy_v9_hex_still_works(db_path):
    db = _setup(db_path)
    master = db.key
    salt = os.urandom(PANIC_SALT_BYTES)
    legacy_hex = derive_pin_key(
        "legacy-panic", salt
    ).hex()
    db._security_update(
        panic_pin_hash=legacy_hex,
        panic_pin_salt=salt,
    )
    assert db.check_panic_pin("legacy-panic")
    assert not db.check_panic_pin("wrong")
    db.close()
    db2 = Database(db_path)
    assert db2.set_master(master)
    assert db2.check_panic_pin("legacy-panic")
    assert not db2.check_panic_pin("wrong")


def test_panic_pin_legacy_upgraded_on_set(db_path):
    db = _setup(db_path)
    master = db.key
    salt = os.urandom(PANIC_SALT_BYTES)
    legacy_hex = derive_pin_key(
        "legacy-panic", salt
    ).hex()
    db._security_update(
        panic_pin_hash=legacy_hex,
        panic_pin_salt=salt,
    )
    assert db.check_panic_pin("legacy-panic")
    db.set_panic_pin("legacy-panic")
    row = db._security_row()
    assert row["panic_pin_hash"].startswith(PANIC_PREFIX_V10)
    assert db.check_panic_pin("legacy-panic")
    assert not db.check_panic_pin("wrong")


def test_panic_pin_corrupted_blob_rejected(db_path):
    db = _setup(db_path)
    db.set_panic_pin("panic123")
    row = db._security_row()
    stored = row["panic_pin_hash"]
    corrupted = (
        stored[:len(PANIC_PREFIX_V10) + 4]
        + "AAAA"
        + stored[len(PANIC_PREFIX_V10) + 8:]
    )
    db._security_update(panic_pin_hash=corrupted)
    assert not db.check_panic_pin("panic123")


def test_panic_pin_missing_salt_returns_false(db_path):
    db = _setup(db_path)
    db.set_panic_pin("panic123")
    db._security_update(panic_pin_salt=None)
    assert not db.check_panic_pin("panic123")


def test_panic_pin_marker_content_verified(db_path):
    db = _setup(db_path)
    db.set_panic_pin("panic123")
    row = db._security_row()
    stored = row["panic_pin_hash"]
    salt = bytes(row["panic_pin_salt"])
    from lanmess_files.config import PANIC_AAD
    from lanmess_files.crypto import aes_gcm_decrypt
    payload = stored[len(PANIC_PREFIX_V10):]
    blob = base64.b64decode(payload)
    nonce = blob[:12]
    ct = blob[12:]
    key = derive_pin_key("panic123", salt)
    marker = aes_gcm_decrypt(key, nonce, ct, PANIC_AAD)
    assert marker == PANIC_MARKER
    assert len(marker) == PANIC_MARKER_BYTES