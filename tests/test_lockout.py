import os
import time

from lanmess_files.config import PIN_LOCKOUT_STEPS
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


def test_no_lockout_initially(db_path):
    db = _setup(db_path)
    assert db.lockout_remaining() == 0


def test_record_failure_below_threshold(db_path):
    db = _setup(db_path)
    for _ in range(4):
        db.record_pin_failure()
    assert db.lockout_remaining() == 0


def test_record_failure_at_threshold(db_path):
    db = _setup(db_path)
    for _ in range(5):
        db.record_pin_failure()
    assert db.lockout_remaining() > 0


def test_record_failure_steps_escalate(db_path):
    db = _setup(db_path)
    for _ in range(10):
        db.record_pin_failure()
    r10 = db.lockout_remaining()
    db.conn.execute(
        "UPDATE security SET lockout_until = 0 WHERE id = 1"
    )
    db.conn.commit()
    for _ in range(10):
        db.record_pin_failure()
    r20 = db.lockout_remaining()
    assert r20 > r10


def test_success_resets_failures(db_path):
    db = _setup(db_path)
    for _ in range(4):
        db.record_pin_failure()
    db.record_pin_success()
    row = db._security_row()
    assert row["failed_attempts"] == 0
    assert row["lockout_until"] == 0


def test_lockout_persists_across_reopen(db_path):
    db = _setup(db_path)
    for _ in range(5):
        db.record_pin_failure()
    lockout = db.lockout_remaining()
    assert lockout > 0
    master = db.key
    db.close()
    db2 = Database(db_path)
    db2.set_master(master)
    assert db2.lockout_remaining() > 0