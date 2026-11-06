import os

from lanmess_files.database import Database
from lanmess_files.tui import LanMessApp


class _FakeApp:
    def __init__(self, db):
        self.db = db

    _apply_peer_ip = LanMessApp._apply_peer_ip


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
        "bob", "10.0.0.5", 50520, "aa" * 32, "bb" * 32
    )
    return db


def test_apply_peer_ip_updates_when_changed(db_path):
    db = _setup(db_path)
    app = _FakeApp(db)
    app._apply_peer_ip({"_peer_ip": "10.0.0.99"}, "bob")
    assert db.get_contact("bob")["ip"] == "10.0.0.99"


def test_apply_peer_ip_noop_when_same(db_path):
    db = _setup(db_path)
    app = _FakeApp(db)
    app._apply_peer_ip({"_peer_ip": "10.0.0.5"}, "bob")
    assert db.get_contact("bob")["ip"] == "10.0.0.5"


def test_apply_peer_ip_noop_without_ip(db_path):
    db = _setup(db_path)
    app = _FakeApp(db)
    app._apply_peer_ip({}, "bob")
    assert db.get_contact("bob")["ip"] == "10.0.0.5"


def test_apply_peer_ip_ignores_unknown_contact(db_path):
    db = _setup(db_path)
    app = _FakeApp(db)
    app._apply_peer_ip({"_peer_ip": "10.0.0.99"}, "nobody")
    assert db.get_contact("nobody") is None


def test_apply_peer_ip_does_not_touch_port(db_path):
    db = _setup(db_path)
    app = _FakeApp(db)
    app._apply_peer_ip({"_peer_ip": "10.0.0.99"}, "bob")
    assert db.get_contact("bob")["port"] == 50520


def test_apply_peer_ip_does_not_touch_state(db_path):
    db = _setup(db_path)
    db.set_contact_state("bob", pending=2, verified=1)
    app = _FakeApp(db)
    app._apply_peer_ip({"_peer_ip": "10.0.0.99"}, "bob")
    c = db.get_contact("bob")
    assert c["pending"] == 2
    assert c["verified"] == 1