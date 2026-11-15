import os

from lanmess_files.database import Database


def test_search_all_messages(db_path):
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
    db.upsert_contact("bob", "10.0.0.5", 50520, "aa" * 32, "bb" * 32)
    db.upsert_contact("charlie", "10.0.0.6", 50521, "cc" * 32, "dd" * 32)
    
    db.add_message("bob", "in", "hello world")
    db.add_message("charlie", "in", "goodbye world")
    db.add_message("bob", "in", "unrelated message")
    
    results = db.search_all_messages("world")
    assert len(results) == 2
    assert results[0]["contact_name"] in ("bob", "charlie")
    assert results[1]["contact_name"] in ("bob", "charlie")
    
    results = db.search_all_messages("unrelated")
    assert len(results) == 1
    assert results[0]["contact_name"] == "bob"
    
    results = db.search_all_messages("nonexistent")
    assert len(results) == 0