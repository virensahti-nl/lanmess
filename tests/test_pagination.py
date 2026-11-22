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
        "bob", "10.0.0.5", 50520, "aa" * 32, "bb" * 32
    )
    return db


def test_get_messages_default_limit(db_path):
    db = _setup(db_path)
    for i in range(10):
        db.add_message("bob", "in", f"msg {i}")
    msgs = db.get_messages("bob")
    assert len(msgs) == 10
    assert msgs[0]["content"] == "msg 0"
    assert msgs[-1]["content"] == "msg 9"


def test_get_messages_with_limit(db_path):
    db = _setup(db_path)
    for i in range(10):
        db.add_message("bob", "in", f"msg {i}")
    msgs = db.get_messages("bob", limit=3)
    assert len(msgs) == 3
    assert msgs[0]["content"] == "msg 7"
    assert msgs[-1]["content"] == "msg 9"


def test_get_messages_with_before_id(db_path):
    db = _setup(db_path)
    for i in range(10):
        db.add_message("bob", "in", f"msg {i}")
    all_msgs = db.get_messages("bob")
    middle_id = all_msgs[5]["id"]
    older = db.get_messages(
        "bob", limit=100, before_id=middle_id
    )
    assert len(older) == 5
    assert older[0]["content"] == "msg 0"
    assert older[-1]["content"] == "msg 4"


def test_get_messages_before_id_strict(db_path):
    db = _setup(db_path)
    db.add_message("bob", "in", "first")
    first_id = db.get_messages("bob")[0]["id"]
    older = db.get_messages(
        "bob", limit=10, before_id=first_id
    )
    assert older == []


def test_pagination_two_full_pages(db_path):
    db = _setup(db_path)
    for i in range(1200):
        db.add_message("bob", "in", f"msg {i}")
    page1 = db.get_messages("bob", limit=500)
    assert len(page1) == 500
    assert page1[-1]["content"] == "msg 1199"
    oldest_page1 = page1[0]["id"]
    page2 = db.get_messages(
        "bob", limit=500, before_id=oldest_page1
    )
    assert len(page2) == 500
    assert page2[-1]["id"] == oldest_page1 - 1
    oldest_page2 = page2[0]["id"]
    page3 = db.get_messages(
        "bob", limit=500, before_id=oldest_page2
    )
    assert len(page3) == 200
    assert page3[0]["content"] == "msg 0"