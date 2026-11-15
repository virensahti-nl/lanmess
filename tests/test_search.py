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


def test_search_finds_all_matches(db_path):
    db = _setup(db_path)
    db.add_message("bob", "in", "hello world")
    db.add_message("bob", "out", "goodbye world")
    db.add_message("bob", "in", "unrelated")
    results = db.search_messages("bob", "world")
    assert len(results) == 2


def test_search_case_insensitive(db_path):
    db = _setup(db_path)
    db.add_message("bob", "in", "Hello WORLD")
    results = db.search_messages("bob", "world")
    assert len(results) == 1


def test_search_no_match(db_path):
    db = _setup(db_path)
    db.add_message("bob", "in", "hello")
    results = db.search_messages("bob", "xyz")
    assert len(results) == 0


def test_search_empty_returns_all(db_path):
    db = _setup(db_path)
    db.add_message("bob", "in", "hello")
    db.add_message("bob", "out", "there")
    results = db.search_messages("bob", "")
    assert len(results) == 2


def test_search_limit(db_path):
    db = _setup(db_path)
    for i in range(100):
        db.add_message("bob", "in", f"match {i}")
    results = db.search_messages("bob", "match", limit=10)
    assert len(results) == 10


def test_search_reply_and_react_fields(db_path):
    db = _setup(db_path)
    db.add_message(
        "bob", "out", "reply text", reply_to=5
    )
    db.add_message(
        "bob", "out", "👍", react_to=6
    )
    results = db.search_messages("bob", "reply")
    assert len(results) == 1
    assert results[0]["reply_to"] == 5