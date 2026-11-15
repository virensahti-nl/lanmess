import os

from lanmess_files.database import Database
from lanmess_files.tui import LanMessApp


class _FakeDiscovery:
    def __init__(self, peers=None):
        self.peers = peers or {}

    def find_by_name(self, name):
        return self.peers.get(name)


class _FakeApp:
    def __init__(self, db, discovery=None):
        self.db = db
        self.discovery = discovery or _FakeDiscovery()

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
        "bob", "100.64.0.5", 50520, "aa" * 32, "bb" * 32
    )
    return db


def test_pinned_contact_not_overwritten(db_path):
    db = _setup(db_path)
    db.set_contact_state("bob", pinned=1)
    app = _FakeApp(db)
    app._apply_peer_ip(
        {"_peer_ip": "192.168.1.42"}, "bob"
    )
    assert db.get_contact("bob")["ip"] == "100.64.0.5"


def test_pinned_survives_many_updates(db_path):
    db = _setup(db_path)
    db.set_contact_state("bob", pinned=1)
    app = _FakeApp(db)
    for _ in range(20):
        app._apply_peer_ip(
            {"_peer_ip": "192.168.1.42"}, "bob"
        )
    assert db.get_contact("bob")["ip"] == "100.64.0.5"


def test_unpinned_contact_overwritten(db_path):
    db = _setup(db_path)
    app = _FakeApp(db)
    app._apply_peer_ip(
        {"_peer_ip": "192.168.1.99"}, "bob"
    )
    assert db.get_contact("bob")["ip"] == "192.168.1.99"


def test_pinned_field_default_zero(db_path):
    db = _setup(db_path)
    assert db.get_contact("bob")["pinned"] == 0


def test_pinned_persists_across_operations(db_path):
    db = _setup(db_path)
    db.set_contact_state("bob", pinned=1)
    db.add_message("bob", "in", "hello")
    assert db.get_contact("bob")["pinned"] == 1