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

    _resolve_peer_address = LanMessApp._resolve_peer_address
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
    return db


def _add_bob(db, ip, port=50520):
    db.upsert_contact(
        name="bob",
        ip=ip,
        port=port,
        ed_public_hex="aa" * 32,
        x25519_public_hex="bb" * 32,
    )


def test_resolve_prefers_discovery_when_live(db_path):
    db = _setup(db_path)
    _add_bob(db, "100.64.0.5")
    discovery = _FakeDiscovery(
        {"bob": {"ip": "192.168.1.42", "tcp_port": 50520}}
    )
    app = _FakeApp(db, discovery)
    ip, port = app._resolve_peer_address(db.get_contact("bob"))
    assert ip == "192.168.1.42"
    assert port == 50520


def test_resolve_uses_stored_ip_when_no_discovery(db_path):
    db = _setup(db_path)
    _add_bob(db, "100.64.0.5")
    app = _FakeApp(db)
    ip, port = app._resolve_peer_address(db.get_contact("bob"))
    assert ip == "100.64.0.5"
    assert port == 50520


def test_resolve_returns_none_when_neither(db_path):
    db = _setup(db_path)
    db.upsert_contact(
        name="bob",
        ip=None,
        port=None,
        ed_public_hex="aa" * 32,
        x25519_public_hex="bb" * 32,
    )
    app = _FakeApp(db)
    ip, port = app._resolve_peer_address(db.get_contact("bob"))
    assert ip is None
    assert port is None


def test_resolve_uses_stored_port_even_if_string(db_path):
    db = _setup(db_path)
    _add_bob(db, "100.64.0.5", 50520)
    app = _FakeApp(db)
    contact = db.get_contact("bob")
    contact["port"] = "50520"
    ip, port = app._resolve_peer_address(contact)
    assert ip == "100.64.0.5"
    assert port == 50520
    assert isinstance(port, int)


def test_apply_peer_ip_overwrites_added_by_ip(db_path):
    db = _setup(db_path)
    _add_bob(db, "100.64.0.5")
    app = _FakeApp(db)
    app._apply_peer_ip({"_peer_ip": "192.168.1.42"}, "bob")
    assert db.get_contact("bob")["ip"] == "192.168.1.42"


def test_resolve_after_apply_returns_new_ip(db_path):
    db = _setup(db_path)
    _add_bob(db, "100.64.0.5")
    app = _FakeApp(db)
    app._apply_peer_ip({"_peer_ip": "192.168.1.42"}, "bob")
    ip, port = app._resolve_peer_address(db.get_contact("bob"))
    assert ip == "192.168.1.42"
    assert port == 50520


def test_readd_by_ip_pins_new_ip_back(db_path):
    db = _setup(db_path)
    _add_bob(db, "100.64.0.5")
    app = _FakeApp(db)
    app._apply_peer_ip({"_peer_ip": "192.168.1.42"}, "bob")
    assert db.get_contact("bob")["ip"] == "192.168.1.42"
    _add_bob(db, "100.64.0.5")
    assert db.get_contact("bob")["ip"] == "100.64.0.5"
    ip, port = app._resolve_peer_address(db.get_contact("bob"))
    assert ip == "100.64.0.5"


def test_readd_by_ip_preserves_state(db_path):
    db = _setup(db_path)
    _add_bob(db, "100.64.0.5")
    db.set_contact_state("bob", pending=0, verified=1)
    _add_bob(db, "192.168.1.42", 50521)
    contact = db.get_contact("bob")
    assert contact["ip"] == "192.168.1.42"
    assert contact["port"] == 50521
    assert contact["verified"] == 1


def test_discovery_still_wins_after_apply_peer_ip(db_path):
    db = _setup(db_path)
    _add_bob(db, "100.64.0.5")
    app = _FakeApp(db)
    app._apply_peer_ip({"_peer_ip": "192.168.1.42"}, "bob")
    app.discovery = _FakeDiscovery(
        {"bob": {"ip": "192.168.1.99", "tcp_port": 50520}}
    )
    ip, port = app._resolve_peer_address(db.get_contact("bob"))
    assert ip == "192.168.1.99"
    assert port == 50520


def test_apply_peer_ip_missing_does_not_overwrite(db_path):
    db = _setup(db_path)
    _add_bob(db, "100.64.0.5")
    app = _FakeApp(db)
    app._apply_peer_ip({}, "bob")
    assert db.get_contact("bob")["ip"] == "100.64.0.5"


def test_apply_peer_ip_same_does_not_rewrite(db_path):
    db = _setup(db_path)
    _add_bob(db, "100.64.0.5")
    app = _FakeApp(db)
    before = db.get_contact("bob")["added_at"]
    app._apply_peer_ip({"_peer_ip": "100.64.0.5"}, "bob")
    after = db.get_contact("bob")["added_at"]
    assert before == after


def test_apply_peer_ip_updates_added_at_on_change(db_path):
    db = _setup(db_path)
    _add_bob(db, "100.64.0.5")
    app = _FakeApp(db)
    before = db.get_contact("bob")["added_at"]
    app._apply_peer_ip({"_peer_ip": "192.168.1.42"}, "bob")
    after = db.get_contact("bob")["added_at"]
    assert after >= before