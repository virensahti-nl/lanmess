import os

from lanmess_files.crypto import decrypt_json, encrypt_json
from lanmess_files.database import Database, _msg_aad_v1, _msg_aad_v2


def _setup(db_path):
    db = Database(db_path)
    master = os.urandom(32)
    db.create_identity(
        name="alice",
        master=master,
        group_key=os.urandom(32),
        ed_private_hex="00" * 32,
        ed_public_hex="11" * 32,
        totp_secret_hex="22" * 20,
        tcp_port=50510,
        x25519_private_hex="33" * 32,
        x25519_public_hex="44" * 32,
    )
    return db, master


def test_identity_blob_no_plaintext_name(db_path):
    db, _ = _setup(db_path)
    row = db.conn.execute(
        "SELECT data_enc FROM identity WHERE id = 1"
    ).fetchone()
    assert "alice" not in row["data_enc"]


def test_identity_blob_no_plaintext_private_key(db_path):
    db, _ = _setup(db_path)
    row = db.conn.execute(
        "SELECT data_enc FROM identity WHERE id = 1"
    ).fetchone()
    assert "00" * 32 not in row["data_enc"]


def test_contact_name_not_in_raw_row(db_path):
    db, _ = _setup(db_path)
    db.upsert_contact(
        "bob", "10.0.0.5", 50520, "aa" * 32, "bb" * 32
    )
    row = db.conn.execute(
        "SELECT name_hash, data_enc FROM contacts"
    ).fetchone()
    assert "bob" not in row["name_hash"]
    assert "bob" not in row["data_enc"]
    assert "10.0.0.5" not in row["data_enc"]
    assert "aa" * 32 not in row["data_enc"]


def test_message_content_not_in_raw_row(db_path):
    db, _ = _setup(db_path)
    db.upsert_contact(
        "bob", "10.0.0.5", 50520, "aa" * 32, "bb" * 32
    )
    db.add_message("bob", "out", "super secret message")
    row = db.conn.execute(
        "SELECT data_enc FROM messages"
    ).fetchone()
    assert "super secret message" not in row["data_enc"]
    assert "secret" not in row["data_enc"]


def test_row_swap_detected_by_aad(db_path):
    db, _ = _setup(db_path)
    db.upsert_contact(
        "bob", "10.0.0.5", 50520, "aa" * 32, "bb" * 32
    )
    db.upsert_contact(
        "carol", "10.0.0.6", 50521, "cc" * 32, "dd" * 32
    )
    db.add_message("bob", "in", "for bob")
    db.add_message("carol", "in", "for carol")
    rows = db.conn.execute(
        "SELECT id, data_enc FROM messages ORDER BY id"
    ).fetchall()
    assert len(rows) == 2
    db.conn.execute(
        "UPDATE messages SET data_enc = ? WHERE id = ?",
        (rows[1]["data_enc"], rows[0]["id"]),
    )
    db.conn.commit()
    assert db.get_messages("bob") == []
    assert len(db.get_messages("carol")) == 1


def test_same_contact_message_reorder_detected(db_path):
    db, _ = _setup(db_path)
    db.upsert_contact(
        "bob", "10.0.0.5", 50520, "aa" * 32, "bb" * 32
    )
    db.add_message("bob", "in", "first")
    db.add_message("bob", "in", "second")
    rows = db.conn.execute(
        "SELECT id, data_enc FROM messages ORDER BY id"
    ).fetchall()
    assert len(rows) == 2
    db.conn.execute(
        "UPDATE messages SET data_enc = ? WHERE id = ?",
        (rows[1]["data_enc"], rows[0]["id"]),
    )
    db.conn.execute(
        "UPDATE messages SET data_enc = ? WHERE id = ?",
        (rows[0]["data_enc"], rows[1]["id"]),
    )
    db.conn.commit()
    assert db.get_messages("bob") == []


def test_same_contact_happy_path(db_path):
    db, _ = _setup(db_path)
    db.upsert_contact(
        "bob", "10.0.0.5", 50520, "aa" * 32, "bb" * 32
    )
    db.add_message("bob", "in", "first")
    db.add_message("bob", "in", "second")
    msgs = db.get_messages("bob")
    assert len(msgs) == 2
    assert msgs[0]["content"] == "first"
    assert msgs[1]["content"] == "second"


def test_message_uses_sequence_aad(db_path):
    db, master = _setup(db_path)
    db.upsert_contact(
        "bob", "10.0.0.5", 50520, "aa" * 32, "bb" * 32
    )
    db.add_message("bob", "in", "hello")
    rows = db.conn.execute(
        "SELECT id, contact_id, data_enc FROM messages"
    ).fetchall()
    assert len(rows) == 1
    data = decrypt_json(
        master,
        rows[0]["data_enc"],
        _msg_aad_v2(rows[0]["contact_id"], rows[0]["id"]),
    )
    assert data["content"] == "hello"


def test_message_with_v1_aad_still_readable(db_path):
    db, master = _setup(db_path)
    db.upsert_contact(
        "bob", "10.0.0.5", 50520, "aa" * 32, "bb" * 32
    )
    contact_id = db._contact_id("bob")
    payload = {
        "direction": "in",
        "content": "legacy",
        "timestamp": 1.0,
        "reply_to": 0,
        "react_to": 0,
    }
    old_ct = encrypt_json(
        master, payload, _msg_aad_v1(contact_id)
    )
    db.conn.execute(
        "INSERT INTO messages (contact_id, data_enc) "
        "VALUES (?, ?)",
        (contact_id, old_ct),
    )
    db.conn.commit()
    msgs = db.get_messages("bob")
    assert len(msgs) == 1
    assert msgs[0]["content"] == "legacy"


def test_contact_swap_detected_by_aad(db_path):
    db, _ = _setup(db_path)
    db.upsert_contact(
        "bob", "10.0.0.5", 50520, "aa" * 32, "bb" * 32
    )
    db.upsert_contact(
        "carol", "10.0.0.6", 50521, "cc" * 32, "dd" * 32
    )
    rows = db.conn.execute(
        "SELECT id, data_enc FROM contacts ORDER BY id"
    ).fetchall()
    db.conn.execute(
        "UPDATE contacts SET data_enc = ? WHERE id = ?",
        (rows[1]["data_enc"], rows[0]["id"]),
    )
    db.conn.commit()
    b = db.get_contact("bob")
    c = db.get_contact("carol")
    assert b is None or b["name"] != "carol"
    assert c is None or c["name"] != "bob"


def test_wrong_master_cannot_decrypt(db_path):
    db, _ = _setup(db_path)
    db.upsert_contact(
        "bob", "10.0.0.5", 50520, "aa" * 32, "bb" * 32
    )
    db.add_message("bob", "in", "x")
    row = db.conn.execute(
        "SELECT data_enc FROM identity WHERE id = 1"
    ).fetchone()
    wrong = os.urandom(32)
    try:
        decrypt_json(wrong, row["data_enc"], b"identity")
        raise AssertionError(
            "decrypted with wrong key"
        )
    except Exception:
        pass


def test_truncated_blob_fails(db_path):
    db, master = _setup(db_path)
    row = db.conn.execute(
        "SELECT data_enc FROM identity WHERE id = 1"
    ).fetchone()
    blob = row["data_enc"]
    truncated = blob[:-10]
    try:
        decrypt_json(master, truncated, b"identity")
        raise AssertionError("truncated blob decrypted")
    except Exception:
        pass