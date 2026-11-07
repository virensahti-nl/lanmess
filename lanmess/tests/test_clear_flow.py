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
    db.upsert_contact(
        name="bob",
        ip="10.0.0.5",
        port=50520,
        ed_public_hex="aa" * 32,
        x25519_public_hex="bb" * 32,
    )
    return db


def test_clear_pending_lifecycle(db_path):
    db = _setup(db_path)
    assert db.get_contact("bob")["clear_pending"] == 0
    db.set_contact_state("bob", clear_pending=1)
    assert db.get_contact("bob")["clear_pending"] == 1
    db.set_contact_state("bob", clear_pending=0)
    assert db.get_contact("bob")["clear_pending"] == 0


def test_clear_messages_empties_list(db_path):
    db = _setup(db_path)
    db.add_message("bob", "in", "hello")
    db.add_message("bob", "out", "hi")
    assert len(db.get_messages("bob")) == 2
    db.clear_messages("bob")
    assert db.get_messages("bob") == []


def test_clear_messages_resets_unread(db_path):
    db = _setup(db_path)
    db.increment_unread("bob")
    db.increment_unread("bob")
    db.add_message("bob", "in", "x")
    assert db.get_contact("bob")["unread_count"] == 2
    db.clear_messages("bob")
    assert db.get_contact("bob")["unread_count"] == 0


def test_clear_pending_does_not_touch_messages_alone(db_path):
    db = _setup(db_path)
    db.add_message("bob", "in", "keep-me")
    db.set_contact_state("bob", clear_pending=1)
    assert len(db.get_messages("bob")) == 1


def test_delete_contact_clears_messages(db_path):
    db = _setup(db_path)
    db.add_message("bob", "in", "x")
    db.delete_contact("bob")
    assert db.get_contact("bob") is None
    assert db.get_messages("bob") == []


def test_audit_logs_clear_local(db_path):
    db = _setup(db_path)
    assert db.append_audit(
        "CLEARED_LOCAL", {"contact": "bob"}
    )
    assert db.verify_audit_chain()


def test_audit_logs_clear_request(db_path):
    db = _setup(db_path)
    assert db.append_audit(
        "CLEAR_REQUEST_SENT", {"contact": "bob"}
    )
    assert db.verify_audit_chain()


def test_audit_logs_clear_accepted(db_path):
    db = _setup(db_path)
    assert db.append_audit(
        "CLEAR_ACCEPTED", {"contact": "bob"}
    )
    assert db.verify_audit_chain()


def test_audit_logs_clear_rejected(db_path):
    db = _setup(db_path)
    assert db.append_audit(
        "CLEAR_REJECTED", {"contact": "bob"}
    )
    assert db.verify_audit_chain()


def test_audit_logs_clear_accepted_local(db_path):
    db = _setup(db_path)
    assert db.append_audit(
        "CLEAR_ACCEPTED_LOCAL",
        {"contact": "bob", "notified": True},
    )
    assert db.verify_audit_chain()