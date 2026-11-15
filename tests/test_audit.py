import os

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


def test_empty_audit_chain_valid(db_path):
    db = _setup(db_path)
    assert db.verify_audit_chain()


def test_single_entry_valid(db_path):
    db = _setup(db_path)
    assert db.append_audit("TEST", {"x": 1})
    assert db.verify_audit_chain()


def test_many_entries_valid(db_path):
    db = _setup(db_path)
    for i in range(20):
        assert db.append_audit("EVENT", {"i": i})
    assert db.verify_audit_chain()


def test_audit_requires_unlock(db_path):
    from lanmess_files.database import Database

    fd, path = db_path + ".x", None
    db = Database(fd)
    assert not db.append_audit("TEST")
    assert not db.verify_audit_chain()
    try:
        db.close()
        os.unlink(fd)
    except Exception:
            pass


def test_tampered_ciphertext_detected(db_path):
    db = _setup(db_path)
    db.append_audit("A")
    db.append_audit("B")
    db.append_audit("C")
    row = db.conn.execute(
        "SELECT id, data_enc FROM audit_log ORDER BY id LIMIT 1"
    ).fetchone()
    original = row["data_enc"]
    tampered = original[:-4] + ("AAAA" if original[-4:] != "AAAA" else "BBBB")
    db.conn.execute(
        "UPDATE audit_log SET data_enc = ? WHERE id = ?",
        (tampered, row["id"]),
    )
    db.conn.commit()
    assert not db.verify_audit_chain()


def test_tampered_prev_hmac_detected(db_path):
    db = _setup(db_path)
    db.append_audit("A")
    db.append_audit("B")
    row = db.conn.execute(
        "SELECT id, prev_hmac FROM audit_log ORDER BY id DESC LIMIT 1"
    ).fetchone()
    db.conn.execute(
        "UPDATE audit_log SET prev_hmac = ? WHERE id = ?",
        ("f" * 64, row["id"]),
    )
    db.conn.commit()
    assert not db.verify_audit_chain()


def test_tampered_own_hmac_detected(db_path):
    db = _setup(db_path)
    db.append_audit("A")
    row = db.conn.execute(
        "SELECT id, own_hmac FROM audit_log LIMIT 1"
    ).fetchone()
    db.conn.execute(
        "UPDATE audit_log SET own_hmac = ? WHERE id = ?",
        ("0" * 64, row["id"]),
    )
    db.conn.commit()
    assert not db.verify_audit_chain()


def test_deletion_from_chain_detected(db_path):
    db = _setup(db_path)
    db.append_audit("A")
    db.append_audit("B")
    db.append_audit("C")
    row = db.conn.execute(
        "SELECT id FROM audit_log ORDER BY id LIMIT 1 OFFSET 1"
    ).fetchone()
    db.conn.execute(
        "DELETE FROM audit_log WHERE id = ?", (row["id"],)
    )
    db.conn.commit()
    assert not db.verify_audit_chain()


def test_persistence_across_reopen(db_path):
    db = _setup(db_path)
    db.append_audit("A")
    db.append_audit("B")
    master = db.key
    db.close()
    db2 = Database(db_path)
    assert db2.set_master(master)
    assert db2.verify_audit_chain()


def test_audit_after_reset_invalid(db_path):
    db = _setup(db_path)
    db.append_audit("A")
    db.reset_all()
    assert not db.verify_audit_chain()


def test_audit_entries_not_decryptable_without_master(db_path):
    db = _setup(db_path)
    db.append_audit("A", {"secret": "value"})
    master = db.key
    db.close()
    db2 = Database(db_path)
    assert not db2.verify_audit_chain()
    assert db2.set_master(master)
    assert db2.verify_audit_chain()