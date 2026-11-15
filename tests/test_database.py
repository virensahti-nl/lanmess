import os

import pytest

from lanmess_files.database import Database, SCHEMA_VERSION


def _make_identity(db, name="alice", master=None, group=None):
    master = master or os.urandom(32)
    group = group or os.urandom(32)
    db.create_identity(
        name=name,
        master=master,
        group_key=group,
        ed_private_hex="00" * 32,
        ed_public_hex="11" * 32,
        totp_secret_hex="22" * 20,
        tcp_port=50510,
        x25519_private_hex="33" * 32,
        x25519_public_hex="44" * 32,
    )
    return master, group


def test_empty_state(db_path):
    db = Database(db_path)
    assert db.get_state() == "empty"


def test_schema_version_is_latest(db_path):
    db = Database(db_path)
    assert db.schema_version() == str(SCHEMA_VERSION)


def test_vault_setup_unlock(db_path):
    db = Database(db_path)
    master = os.urandom(32)
    assert db.setup_vault(master, "mypin1234A!")
    assert db.has_vault()
    assert db.unlock_vault("mypin1234A!") == master


def test_vault_wrong_pin(db_path):
    db = Database(db_path)
    master = os.urandom(32)
    db.setup_vault(master, "mypin1234A!")
    assert db.unlock_vault("wrong") is None


def test_create_identity_stores_group_key(db_path):
    db = Database(db_path)
    master, group = _make_identity(db)
    ident = db.get_identity()
    assert ident["name"] == "alice"
    assert ident["group_key_hex"] == group.hex()
    assert db.group_key == group


def test_wrong_master_cannot_read(db_path):
    db = Database(db_path)
    _make_identity(db)
    db2 = Database(db_path)
    assert not db2.set_master(os.urandom(32))
    assert db2.get_identity() is None


def test_group_code_alone_cannot_unlock(db_path):
    db = Database(db_path)
    master, group = _make_identity(db)
    db.setup_vault(master, "mypin1234A!")
    db2 = Database(db_path)
    assert not db2.set_master(group)
    assert db2.get_identity() is None


def test_pin_alone_can_unlock(db_path):
    db = Database(db_path)
    master, _ = _make_identity(db)
    db.setup_vault(master, "mypin1234A!")
    db2 = Database(db_path)
    recovered = db2.unlock_vault("mypin1234A!")
    assert recovered == master
    assert db2.set_master(recovered)
    assert db2.get_identity()["name"] == "alice"


def test_contact_roundtrip_new_fields(db_path):
    db = Database(db_path)
    _make_identity(db)
    db.upsert_contact(
        name="bob",
        ip="10.0.0.5",
        port=50520,
        ed_public_hex="aa" * 32,
        x25519_public_hex="bb" * 32,
    )
    c = db.get_contact("bob")
    assert c["session_established"] == 0
    assert c["verified"] == 0
    assert c["unread_count"] == 0
    assert c["send_chain_key_hex"] == ""


def test_session_state_roundtrip(db_path):
    db = Database(db_path)
    _make_identity(db)
    db.upsert_contact("bob", "10.0.0.5", 50520, "aa" * 32, "bb" * 32)
    send_chain = os.urandom(32).hex()
    recv_chain = os.urandom(32).hex()
    db.set_contact_state(
        "bob",
        session_established=1,
        send_chain_key_hex=send_chain,
        recv_chain_key_hex=recv_chain,
        send_counter=3,
        recv_counter=7,
    )
    c = db.get_contact("bob")
    assert c["session_established"] == 1
    assert c["send_counter"] == 3
    assert c["recv_counter"] == 7


def test_messages_roundtrip(db_path):
    db = Database(db_path)
    _make_identity(db)
    db.upsert_contact("bob", "10.0.0.5", 50520, "aa" * 32, "bb" * 32)
    db.add_message("bob", "out", "hello")
    db.add_message("bob", "in", "hi")
    msgs = db.get_messages("bob")
    assert len(msgs) == 2
    assert msgs[0]["content"] == "hello"
    assert msgs[1]["content"] == "hi"


def test_reset_wipes_everything(db_path):
    db = Database(db_path)
    master, _ = _make_identity(db)
    db.setup_vault(master, "mypin1234A!")
    db.append_audit("X")
    db.reset_all()
    assert db.get_state() == "empty"
    assert db.schema_version() == str(SCHEMA_VERSION)


def test_migrate_v4_to_v5_creates_new_master(db_path):
    db = Database(db_path)
    old_master = os.urandom(32)
    group = os.urandom(32)
    db.create_identity(
        name="alice",
        master=old_master,
        group_key=group,
        ed_private_hex="00" * 32,
        ed_public_hex="11" * 32,
        totp_secret_hex="22" * 20,
        tcp_port=50510,
        x25519_private_hex="33" * 32,
        x25519_public_hex="44" * 32,
    )
    db.upsert_contact("bob", "10.0.0.5", 50520, "aa" * 32, "bb" * 32)
    db.add_message("bob", "out", "before")
    db.set_schema_version(4)
    new_master = db.migrate_to_v5(old_master, "strongpin123A!")
    assert new_master is not None
    assert new_master != old_master
    db2 = Database(db_path)
    assert db2.set_master(new_master)
    assert db2.get_identity()["name"] == "alice"
    msgs = db2.get_messages("bob")
    assert len(msgs) == 1
    assert msgs[0]["content"] == "before"