import os
import pytest
from lanmess_files.database import Database

def test_update_contact_keys(db_path):
    db = Database(db_path)
    db.create_identity(
        name="alice", master=os.urandom(32), group_key=os.urandom(32),
        ed_private_hex="00"*32, ed_public_hex="11"*32,
        totp_secret_hex="22"*20, tcp_port=50510,
        x25519_private_hex="33"*32, x25519_public_hex="44"*32
    )
    db.upsert_contact("bob", "10.0.0.5", 50520, "aa"*32, "bb"*32)
    c = db.get_contact("bob")
    assert c["ed_public_hex"] == "aa"*32
    db.update_contact_keys("bob", "cc"*32, "dd"*32)
    c2 = db.get_contact("bob")
    assert c2["ed_public_hex"] == "cc"*32
    assert c2["x25519_public_hex"] == "dd"*32