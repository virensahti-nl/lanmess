import os

from lanmess_files.crypto import decrypt_json, encrypt_json
from lanmess_files.database import Database, SCHEMA_VERSION


def _create_base(db_path):
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
    db.upsert_contact(
        "bob", "10.0.0.5", 50520, "aa" * 32, "bb" * 32
    )
    db.add_message("bob", "in", "before migration")
    return db, old_master, group


def _strip_group_key_hex(db, master):
    row = db.conn.execute(
        "SELECT data_enc FROM identity WHERE id = 1"
    ).fetchone()
    data = decrypt_json(master, row["data_enc"], b"identity")
    data.pop("group_key_hex", None)
    enc = encrypt_json(master, data, b"identity")
    db.conn.execute(
        "UPDATE identity SET data_enc = ? WHERE id = 1",
        (enc,),
    )
    db.conn.commit()


def test_v5_to_v6_creates_audit_log(db_path):
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
    db.conn.execute("DROP TABLE audit_log")
    db.conn.commit()
    db.set_schema_version(5)
    db.close()
    db2 = Database(db_path)
    assert db2.schema_version() == str(SCHEMA_VERSION)
    row = db2.conn.execute(
        "SELECT name FROM sqlite_master "
        "WHERE type='table' AND name='audit_log'"
    ).fetchone()
    assert row is not None


def test_v5_to_v6_preserves_data(db_path):
    db, master, group = _create_base(db_path)
    db.conn.execute("DROP TABLE audit_log")
    db.conn.commit()
    db.set_schema_version(5)
    db.close()
    db2 = Database(db_path)
    assert db2.set_master(master)
    ident = db2.get_identity()
    assert ident["name"] == "alice"
    assert ident["group_key_hex"] == group.hex()
    assert db2.get_contact("bob") is not None
    msgs = db2.get_messages("bob")
    assert len(msgs) == 1
    assert msgs[0]["content"] == "before migration"


def test_v4_migration_without_group_key_hex(db_path):
    db = Database(db_path)
    master = os.urandom(32)
    db.create_identity(
        name="alice",
        master=master,
        group_key=master,
        ed_private_hex="00" * 32,
        ed_public_hex="11" * 32,
        totp_secret_hex="22" * 20,
        tcp_port=50510,
        x25519_private_hex="33" * 32,
        x25519_public_hex="44" * 32,
    )
    _strip_group_key_hex(db, master)
    db.set_schema_version(4)
    new_master = db.migrate_to_v5(
        master, "strongpin123A!"
    )
    assert new_master is not None
    assert new_master != master
    db2 = Database(db_path)
    assert db2.set_master(new_master)
    ident = db2.get_identity()
    assert ident["group_key_hex"] == master.hex()


def test_v4_migration_preserves_messages(db_path):
    db = Database(db_path)
    master = os.urandom(32)
    db.create_identity(
        name="alice",
        master=master,
        group_key=master,
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
    db.add_message("bob", "in", "before migration")
    _strip_group_key_hex(db, master)
    db.set_schema_version(4)
    new_master = db.migrate_to_v5(
        master, "strongpin123A!"
    )
    assert new_master is not None
    db2 = Database(db_path)
    assert db2.set_master(new_master)
    c = db2.get_contact("bob")
    assert c is not None
    msgs = db2.get_messages("bob")
    assert len(msgs) == 1
    assert msgs[0]["content"] == "before migration"


def test_v4_migration_rejects_wrong_master(db_path):
    db, _old_master, _group = _create_base(db_path)
    db.set_schema_version(4)
    wrong = os.urandom(32)
    result = db.migrate_to_v5(wrong, "strongpin123A!")
    assert result is None


def test_v4_migration_replaces_vault(db_path):
    db = Database(db_path)
    master = os.urandom(32)
    db.create_identity(
        name="alice",
        master=master,
        group_key=master,
        ed_private_hex="00" * 32,
        ed_public_hex="11" * 32,
        totp_secret_hex="22" * 20,
        tcp_port=50510,
        x25519_private_hex="33" * 32,
        x25519_public_hex="44" * 32,
    )
    db.setup_vault(master, "oldpin1234A!")
    db.set_schema_version(4)
    new_master = db.migrate_to_v5(
        master, "newpin12345B!"
    )
    assert new_master is not None
    assert db.unlock_vault("newpin12345B!") == new_master
    assert db.unlock_vault("oldpin1234A!") is None