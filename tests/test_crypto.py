import os

import pytest

from lanmess_files.crypto import (
    chain_advance,
    chain_message_key,
    compute_safety_number,
    compute_secure_code_tag,
    compute_totp,
    decrypt_json,
    derive_group_key,
    derive_lookup_key,
    derive_pin_key,
    derive_session_chains,
    ed_private_from_bytes,
    ed_private_to_bytes,
    ed_public_from_bytes,
    ed_public_to_bytes,
    encrypt_json,
    generate_ed25519_private,
    pad_message,
    sign_bytes,
    unpad_message,
    verify_bytes,
    verify_totp,
    x25519_generate,
    x25519_private_from_bytes,
    x25519_private_to_bytes,
    x25519_public_from_bytes,
    x25519_public_to_bytes,
)


def test_group_key_deterministic():
    a = derive_group_key("correct horse battery staple")
    b = derive_group_key("correct horse battery staple")
    assert a == b
    assert len(a) == 32


def test_group_key_different_input():
    assert derive_group_key("a") != derive_group_key("b")


def test_lookup_key_distinct_from_group_key():
    gk = derive_group_key("hello world how are you")
    lk = derive_lookup_key(gk)
    assert gk != lk
    assert len(lk) == 32


def test_pin_key_deterministic():
    salt = os.urandom(16)
    a = derive_pin_key("mypin12345X", salt)
    b = derive_pin_key("mypin12345X", salt)
    assert a == b


def test_pin_key_salt_sensitive():
    salt1 = os.urandom(16)
    salt2 = os.urandom(16)
    assert derive_pin_key("mypin12345X", salt1) != derive_pin_key(
        "mypin12345X", salt2
    )


def test_pin_key_pin_sensitive():
    salt = os.urandom(16)
    assert derive_pin_key("pinA1234567", salt) != derive_pin_key(
        "pinB1234567", salt
    )


def test_json_roundtrip():
    key = os.urandom(32)
    data = {"a": 1, "b": "two", "c": [3, 4]}
    blob = encrypt_json(key, data, b"test")
    assert decrypt_json(key, blob, b"test") == data


def test_json_aad_binding():
    key = os.urandom(32)
    blob = encrypt_json(key, {"x": 1}, b"aad1")
    with pytest.raises(Exception):
        decrypt_json(key, blob, b"aad2")


def test_json_wrong_key():
    blob = encrypt_json(os.urandom(32), {"x": 1}, b"aad")
    with pytest.raises(Exception):
        decrypt_json(os.urandom(32), blob, b"aad")


def test_ed25519_sign_verify():
    sk = generate_ed25519_private()
    pk = sk.public_key()
    sig = sign_bytes(sk, b"hello")
    assert verify_bytes(pk, sig, b"hello")
    assert not verify_bytes(pk, sig, b"hello!")


def test_ed25519_serialization_roundtrip():
    sk = generate_ed25519_private()
    sk2 = ed_private_from_bytes(ed_private_to_bytes(sk))
    pk2 = ed_public_from_bytes(ed_public_to_bytes(sk.public_key()))
    sig = sign_bytes(sk2, b"test")
    assert verify_bytes(pk2, sig, b"test")


def test_x25519_serialization_roundtrip():
    sk = x25519_generate()
    sk2 = x25519_private_from_bytes(x25519_private_to_bytes(sk))
    pk = sk2.public_key()
    pk2 = x25519_public_from_bytes(x25519_public_to_bytes(pk))
    peer = x25519_generate()
    shared_a = sk2.exchange(peer.public_key())
    shared_b = peer.exchange(pk2)
    assert shared_a == shared_b


def test_session_chains_symmetric():
    alice = x25519_generate()
    bob = x25519_generate()
    alice_pub = x25519_public_to_bytes(alice.public_key())
    bob_pub = x25519_public_to_bytes(bob.public_key())
    shared_a = alice.exchange(bob.public_key())
    shared_b = bob.exchange(alice.public_key())
    assert shared_a == shared_b
    chains_a = derive_session_chains(shared_a, alice_pub, bob_pub)
    chains_b = derive_session_chains(shared_b, bob_pub, alice_pub)
    assert chains_a == chains_b
    assert len(chains_a) == 64


def test_session_chains_differ_per_ephemeral():
    alice = x25519_generate()
    bob = x25519_generate()
    alice_pub = x25519_public_to_bytes(alice.public_key())
    bob_pub = x25519_public_to_bytes(bob.public_key())
    shared = alice.exchange(bob.public_key())
    c1 = derive_session_chains(shared, alice_pub, bob_pub)
    alice2 = x25519_generate()
    alice2_pub = x25519_public_to_bytes(alice2.public_key())
    shared2 = alice2.exchange(bob.public_key())
    c2 = derive_session_chains(shared2, alice2_pub, bob_pub)
    assert c1 != c2


def test_chain_advance_one_way():
    k = os.urandom(32)
    a = chain_advance(k)
    b = chain_advance(a)
    assert a != k
    assert b != a
    assert chain_advance(k) == a


def test_chain_message_key_distinct_from_chain():
    k = os.urandom(32)
    mk = chain_message_key(k)
    assert mk != k
    assert mk != chain_advance(k)
    assert chain_message_key(k) == mk


def test_chain_forward_secrecy():
    chain = os.urandom(32)
    mk1 = chain_message_key(chain)
    chain = chain_advance(chain)
    mk2 = chain_message_key(chain)
    assert mk1 != mk2


def test_chain_sequence_ten_messages():
    send = os.urandom(32)
    recv = send
    for _ in range(10):
        assert chain_message_key(send) == chain_message_key(recv)
        send = chain_advance(send)
        recv = chain_advance(recv)


def test_pad_roundtrip_all_sizes():
    for size in (0, 1, 5, 100, 255, 256, 257, 512, 1000, 8000):
        data = os.urandom(size)
        padded = pad_message(data)
        assert len(padded) % 256 == 0
        assert len(padded) >= len(data) + 4
        assert unpad_message(padded) == data


def test_pad_hides_small_sizes():
    sizes = [pad_message(os.urandom(n)) for n in (1, 10, 50, 100)]
    lengths = {len(p) for p in sizes}
    assert len(lengths) == 1


def test_pad_rejects_corrupted_header():
    with pytest.raises(ValueError):
        unpad_message(b"\x00\x00")


def test_pad_rejects_length_overflow():
    import struct

    bad = struct.pack(">I", 999) + b"short"
    with pytest.raises(ValueError):
        unpad_message(bad)


def test_safety_number_symmetric():
    a = os.urandom(32).hex()
    b = os.urandom(32).hex()
    assert compute_safety_number(a, b) == compute_safety_number(b, a)


def test_safety_number_distinct():
    a = os.urandom(32).hex()
    b = os.urandom(32).hex()
    c = os.urandom(32).hex()
    assert compute_safety_number(a, b) != compute_safety_number(a, c)


def test_safety_number_format():
    a = os.urandom(32).hex()
    b = os.urandom(32).hex()
    s = compute_safety_number(a, b)
    groups = s.split(" ")
    assert len(groups) == 12
    for g in groups:
        assert len(g) == 5
        assert g.isdigit()


def test_safety_number_stable():
    a = "aa" * 32
    b = "bb" * 32
    s1 = compute_safety_number(a, b)
    s2 = compute_safety_number(a, b)
    assert s1 == s2


def test_totp_current():
    secret = os.urandom(20)
    assert verify_totp(secret, compute_totp(secret))


def test_totp_previous_period_accepted():
    secret = os.urandom(20)
    assert verify_totp(secret, compute_totp(secret, -1))


def test_totp_wrong_rejected():
    secret = os.urandom(20)
    assert not verify_totp(secret, "00000000")


def test_totp_format():
    secret = os.urandom(20)
    code = compute_totp(secret)
    assert len(code) == 8
    assert code.isdigit()


def test_code_tag_deterministic():
    code = "12345678"
    lk = derive_lookup_key(derive_group_key("x" * 20))
    assert compute_secure_code_tag(lk, code) == compute_secure_code_tag(
        lk, code
    )


def test_code_tag_changes_with_lookup_key():
    code = "12345678"
    lk1 = derive_lookup_key(derive_group_key("aaaa" * 5))
    lk2 = derive_lookup_key(derive_group_key("bbbb" * 5))
    assert compute_secure_code_tag(lk1, code) != compute_secure_code_tag(
        lk2, code
    )


def test_code_tag_changes_with_code():
    lk = derive_lookup_key(derive_group_key("x" * 20))
    assert compute_secure_code_tag(lk, "11111111") != compute_secure_code_tag(
        lk, "22222222"
    )