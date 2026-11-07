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


def test_session_teardown_clears_chain(db_path):
    db = _setup(db_path)
    db.set_contact_state(
        "bob",
        chat_started=1,
        session_established=1,
        send_chain_key_hex="aa" * 32,
        recv_chain_key_hex="bb" * 32,
        send_counter=5,
        recv_counter=5,
    )
    db.set_contact_state(
        "bob",
        chat_started=0,
        session_established=0,
        send_chain_key_hex="",
        recv_chain_key_hex="",
        send_counter=0,
        recv_counter=0,
        session_local_eph_sk_hex="",
        session_peer_eph_pub_hex="",
    )
    c = db.get_contact("bob")
    assert c["chat_started"] == 0
    assert c["session_established"] == 0
    assert c["send_chain_key_hex"] == ""
    assert c["recv_chain_key_hex"] == ""
    assert c["send_counter"] == 0
    assert c["recv_counter"] == 0


def test_verify_and_react_roundtrip(db_path):
    db = _setup(db_path)
    db.add_message(
        "bob", "out", "hi", reply_to=3
    )
    db.add_message(
        "bob", "out", "👍", react_to=4
    )
    msgs = db.get_messages("bob")
    assert msgs[0]["reply_to"] == 3
    assert msgs[1]["react_to"] == 4
    assert msgs[0]["react_to"] == 0
    assert msgs[1]["reply_to"] == 0