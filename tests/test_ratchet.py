import os

from lanmess_files.crypto import (
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    chain_advance,
    chain_message_key,
    derive_session_chains,
    pad_message,
    unpad_message,
    x25519_generate,
    x25519_public_to_bytes,
)


def _setup_session():
    alice = x25519_generate()
    bob = x25519_generate()
    alice_pub = x25519_public_to_bytes(alice.public_key())
    bob_pub = x25519_public_to_bytes(bob.public_key())
    shared_a = alice.exchange(bob.public_key())
    shared_b = bob.exchange(alice.public_key())
    chains_a = derive_session_chains(shared_a, alice_pub, bob_pub)
    chains_b = derive_session_chains(shared_b, bob_pub, alice_pub)
    alice_send = chains_a[0:32]
    alice_recv = chains_a[32:64]
    bob_send = chains_b[32:64]
    bob_recv = chains_b[0:32]
    return alice_send, alice_recv, bob_send, bob_recv


def _encrypt(chain, plaintext, sender, counter):
    key = chain_message_key(chain)
    nonce = os.urandom(12)
    padded = pad_message(plaintext.encode("utf-8"))
    aad = f"{sender}:{counter}".encode("utf-8")
    return nonce, aes_gcm_encrypt(key, padded, nonce, aad)


def _decrypt(chain, nonce, ct, sender, counter):
    key = chain_message_key(chain)
    aad = f"{sender}:{counter}".encode("utf-8")
    padded = aes_gcm_decrypt(key, nonce, ct, aad)
    return unpad_message(padded).decode("utf-8")


def test_chains_align_between_peers():
    alice_send, _, bob_send, _ = _setup_session()
    assert alice_send != bob_send


def test_single_message_roundtrip():
    alice_send, _, _, bob_recv = _setup_session()
    nonce, ct = _encrypt(alice_send, "hello bob", "alice", 1)
    assert _decrypt(bob_recv, nonce, ct, "alice", 1) == "hello bob"


def test_sequence_of_messages():
    alice_send, _, _, bob_recv = _setup_session()
    payloads = ["m1", "m2", "m3", "m4", "m5"]
    send_chain = alice_send
    recv_chain = bob_recv
    for i, payload in enumerate(payloads, start=1):
        nonce, ct = _encrypt(send_chain, payload, "alice", i)
        assert _decrypt(recv_chain, nonce, ct, "alice", i) == payload
        send_chain = chain_advance(send_chain)
        recv_chain = chain_advance(recv_chain)


def test_bidirectional_messages():
    alice_send, alice_recv, bob_send, bob_recv = _setup_session()
    a_out = alice_send
    a_in = alice_recv
    b_out = bob_send
    b_in = bob_recv
    for i in range(1, 4):
        nonce_a, ct_a = _encrypt(a_out, f"a{i}", "alice", i)
        assert _decrypt(b_in, nonce_a, ct_a, "alice", i) == f"a{i}"
        a_out = chain_advance(a_out)
        b_in = chain_advance(b_in)
        nonce_b, ct_b = _encrypt(b_out, f"b{i}", "bob", i)
        assert _decrypt(a_in, nonce_b, ct_b, "bob", i) == f"b{i}"
        b_out = chain_advance(b_out)
        a_in = chain_advance(a_in)


def test_replay_with_same_chain_rejected():
    alice_send, _, _, bob_recv = _setup_session()
    nonce, ct = _encrypt(alice_send, "one", "alice", 1)
    assert _decrypt(bob_recv, nonce, ct, "alice", 1) == "one"
    next_chain = chain_advance(bob_recv)
    try:
        _decrypt(next_chain, nonce, ct, "alice", 1)
    except Exception:
        return
    raise AssertionError("replay with advanced chain must fail")


def test_wrong_counter_aad_rejected():
    alice_send, _, _, bob_recv = _setup_session()
    nonce, ct = _encrypt(alice_send, "one", "alice", 1)
    try:
        _decrypt(bob_recv, nonce, ct, "alice", 2)
    except Exception:
        return
    raise AssertionError("wrong counter must fail")


def test_wrong_sender_aad_rejected():
    alice_send, _, _, bob_recv = _setup_session()
    nonce, ct = _encrypt(alice_send, "one", "alice", 1)
    try:
        _decrypt(bob_recv, nonce, ct, "bob", 1)
    except Exception:
        return
    raise AssertionError("wrong sender must fail")


def test_old_chain_key_cannot_decrypt_new():
    alice_send, _, _, bob_recv = _setup_session()
    old_chain = bob_recv
    chain_at_4 = old_chain
    for _ in range(3):
        chain_at_4 = chain_advance(chain_at_4)
    nonce, ct = _encrypt(chain_at_4, "target", "alice", 4)
    assert _decrypt(chain_at_4, nonce, ct, "alice", 4) == "target"
    try:
        _decrypt(old_chain, nonce, ct, "alice", 4)
    except Exception:
        return
    raise AssertionError(
        "old chain must not decrypt later message (forward secrecy)"
    )


def test_corrupted_ciphertext_rejected():
    alice_send, _, _, bob_recv = _setup_session()
    nonce, ct = _encrypt(alice_send, "one", "alice", 1)
    bad = bytes([ct[0] ^ 0xFF]) + ct[1:]
    try:
        _decrypt(bob_recv, nonce, bad, "alice", 1)
    except Exception:
        return
    raise AssertionError("corrupted ciphertext must fail")


def test_padding_hides_length():
    alice_send, _, _, _ = _setup_session()
    send = alice_send
    lengths = []
    for msg in ["a", "a" * 20, "a" * 100, "a" * 200]:
        nonce, ct = _encrypt(send, msg, "alice", 1)
        lengths.append(len(ct))
        send = chain_advance(send)
    assert len(set(lengths)) == 1