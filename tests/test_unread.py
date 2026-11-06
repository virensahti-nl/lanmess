import os

from lanmess_files.database import Database
from lanmess_files.config import UNREAD_MAX


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
    db.upsert_contact(
        name="bob",
        ip="10.0.0.5",
        port=50520,
        ed_public_hex="aa" * 32,
        x25519_public_hex="bb" * 32,
    )
    return db


def test_unread_starts_zero(db_path):
    db = _setup(db_path)
    c = db.get_contact("bob")
    assert c["unread_count"] == 0


def test_increment_unread(db_path):
    db = _setup(db_path)
    db.increment_unread("bob")
    assert db.get_contact("bob")["unread_count"] == 1
    db.increment_unread("bob")
    assert db.get_contact("bob")["unread_count"] == 2


def test_unread_caps_at_max(db_path):
    db = _setup(db_path)
    for _ in range(UNREAD_MAX + 20):
        db.increment_unread("bob")
    assert db.get_contact("bob")["unread_count"] == UNREAD_MAX


def test_clear_unread(db_path):
    db = _setup(db_path)
    db.increment_unread("bob")
    db.increment_unread("bob")
    db.clear_unread("bob")
    assert db.get_contact("bob")["unread_count"] == 0


def test_clear_unread_noop_when_zero(db_path):
    db = _setup(db_path)
    db.clear_unread("bob")
    assert db.get_contact("bob")["unread_count"] == 0


def test_total_unread(db_path):
    db = _setup(db_path)
    db.upsert_contact(
        name="carol",
        ip="10.0.0.6",
        port=50521,
        ed_public_hex="cc" * 32,
        x25519_public_hex="dd" * 32,
    )
    db.increment_unread("bob")
    db.increment_unread("bob")
    db.increment_unread("carol")
    assert db.total_unread() == 3


def test_increment_unknown_contact_noop(db_path):
    db = _setup(db_path)
    db.increment_unread("nobody")
    assert db.total_unread() == 0


def test_clear_unknown_contact_noop(db_path):
    db = _setup(db_path)
    db.clear_unread("nobody")
    assert db.total_unread() == 0