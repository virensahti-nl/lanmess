import os

from lanmess_files.crypto import (
    compute_name_hash,
    decrypt_json,
    derive_lookup_key,
    encrypt_json,
)
from lanmess_files.database import (
    Database,
    SCHEMA_VERSION,
    _msg_aad_v1,
    _msg_aad_v2,
)


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


def test_v1_schema_migration_to_v3(db_path):
    db = Database(db_path)
    group_key = os.urandom(32)
    db.conn.execute("DROP TABLE IF EXISTS messages")
    db.conn.execute("DROP TABLE IF EXISTS contacts")
    db.conn.execute("DROP TABLE IF EXISTS identity")
    db.conn.execute("DROP TABLE IF EXISTS vault")
    db.conn.execute("DROP TABLE IF EXISTS audit_log")
    db.conn.execute("DROP TABLE IF EXISTS security")
    db.conn.execute("DROP TABLE IF EXISTS meta")
    db.conn.execute(
        "CREATE TABLE identity ("
        "id INTEGER PRIMARY KEY CHECK (id = 1),"
        "name TEXT NOT NULL,"
        "ed_private_hex TEXT NOT NULL,"
        "ed_public_hex TEXT NOT NULL,"
        "totp_secret_hex TEXT NOT NULL,"
        "tcp_port INTEGER NOT NULL)"
    )
    db.conn.execute(
        "CREATE TABLE contacts ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "name TEXT NOT NULL,"
        "ip TEXT,"
        "port INTEGER,"
        "ed_public_hex TEXT NOT NULL,"
        "chat_started INTEGER DEFAULT 0,"
        "incoming_request INTEGER DEFAULT 0,"
        "blocked INTEGER DEFAULT 0,"
        "pending INTEGER DEFAULT 0,"
        "clear_pending INTEGER DEFAULT 0,"
        "added_at REAL NOT NULL)"
    )
    db.conn.execute(
        "CREATE TABLE messages ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "contact_name TEXT NOT NULL,"
        "direction TEXT NOT NULL,"
        "content TEXT NOT NULL,"
        "timestamp REAL NOT NULL)"
    )
    db.conn.execute(
        "INSERT INTO identity VALUES "
        "(1, 'alice', ?, ?, ?, 50510)",
        ("00" * 32, "11" * 32, "22" * 20),
    )
    db.conn.execute(
        "INSERT INTO contacts "
        "(name, ip, port, ed_public_hex, added_at) "
        "VALUES ('bob', '10.0.0.5', 50520, ?, 1.0)",
        ("aa" * 32,),
    )
    db.conn.execute(
        "INSERT INTO messages "
        "(contact_name, direction, content, timestamp) "
        "VALUES ('bob', 'in', 'old', 12345.0)"
    )
    db.conn.commit()
    db.set_schema_version(1)
    db.close()

    db2 = Database(db_path)
    ok = db2.migrate_to_v3(group_key, "1")
    assert ok
    assert db2.set_master(group_key)
    ident = db2.get_identity()
    assert ident["name"] == "alice"
    assert "x25519_private_hex" in ident
    contact = db2.get_contact("bob")
    assert contact is not None
    msgs = db2.get_messages("bob")
    assert len(msgs) == 1
    assert msgs[0]["content"] == "old"


def test_v2_schema_migration_to_v3(db_path):
    db = Database(db_path)
    group_key = os.urandom(32)
    lookup_key = derive_lookup_key(group_key)
    db.conn.execute("DROP TABLE IF EXISTS messages")
    db.conn.execute("DROP TABLE IF EXISTS contacts")
    db.conn.execute("DROP TABLE IF EXISTS identity")
    db.conn.execute("DROP TABLE IF EXISTS vault")
    db.conn.execute("DROP TABLE IF EXISTS audit_log")
    db.conn.execute("DROP TABLE IF EXISTS security")
    db.conn.execute("DROP TABLE IF EXISTS meta")
    db._create_tables()
    identity_data = {
        "name": "alice",
        "ed_private_hex": "00" * 32,
        "ed_public_hex": "11" * 32,
        "totp_secret_hex": "22" * 20,
        "tcp_port": 50510,
    }
    db.conn.execute(
        "INSERT INTO identity (id, data_enc) VALUES (1, ?)",
        (encrypt_json(group_key, identity_data, b"identity"),),
    )
    name_hash = compute_name_hash(lookup_key, "bob")
    aad = b"contact:" + name_hash.encode()
    contact_data = {
        "name": "bob",
        "ip": "10.0.0.5",
        "port": 50520,
        "ed_public_hex": "aa" * 32,
        "chat_started": 0,
        "incoming_request": 0,
        "blocked": 0,
        "pending": 0,
        "clear_pending": 0,
        "added_at": 1.0,
    }
    db.conn.execute(
        "INSERT INTO contacts (name_hash, data_enc) "
        "VALUES (?, ?)",
        (name_hash, encrypt_json(group_key, contact_data, aad)),
    )
    db.conn.commit()
    db.set_schema_version(2)
    db.close()

    db2 = Database(db_path)
    ok = db2.migrate_to_v3(group_key, "2")
    assert ok
    assert db2.set_master(group_key)
    contact = db2.get_contact("bob")
    assert contact is not None
    assert contact["x25519_public_hex"] == ""


def test_v8_msg_aad_migration_on_set_master(db_path):
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
    contact_id = db._contact_id("bob")
    payload = {
        "direction": "in",
        "content": "legacy message",
        "timestamp": 12345.0,
        "reply_to": 0,
        "react_to": 0,
    }
    old_ct = encrypt_json(
        db.key, payload, _msg_aad_v1(contact_id)
    )
    db.conn.execute(
        "INSERT INTO messages (contact_id, data_enc) "
        "VALUES (?, ?)",
        (contact_id, old_ct),
    )
    db.conn.commit()
    master = db.key
    db.set_schema_version(8)
    db._set_meta("msg_aad_version", "1")
    db.close()

    db2 = Database(db_path)
    assert db2.set_master(master)
    assert db2._get_meta("msg_aad_version") == "2"
    msgs = db2.get_messages("bob")
    assert len(msgs) == 1
    assert msgs[0]["content"] == "legacy message"
    row = db2.conn.execute(
        "SELECT id, contact_id, data_enc FROM messages"
    ).fetchone()
    data = decrypt_json(
        master,
        row["data_enc"],
        _msg_aad_v2(row["contact_id"], row["id"]),
    )
    assert data["content"] == "legacy message"