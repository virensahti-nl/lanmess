import os

import pytest

from lanmess_files.crypto import (
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    chain_advance,
    chain_message_key,
    pad_message,
    unpad_message,
)


def _encrypt_at(chain, message, sender, counter):
    if isinstance(message, str):
        message = message.encode("utf-8")
    key = chain_message_key(chain)
    nonce = os.urandom(12)
    ct = aes_gcm_encrypt(
        key, pad_message(message), nonce,
        f"{sender}:{counter}".encode("utf-8"),
    )
    return nonce, ct


def _decrypt_at(chain, nonce, ct, sender, counter):
    key = chain_message_key(chain)
    padded = aes_gcm_decrypt(
        key, nonce, ct,
        f"{sender}:{counter}".encode("utf-8"),
    )
    return unpad_message(padded).decode("utf-8")


def test_future_chain_cannot_decrypt_past():
    chain_0 = os.urandom(32)
    future = chain_0
    for _ in range(5):
        future = chain_advance(future)
    nonce, ct = _encrypt_at(chain_0, "past", "a", 1)
    with pytest.raises(Exception):
        _decrypt_at(future, nonce, ct, "a", 1)


def test_skipping_counter_fails():
    chain_0 = os.urandom(32)
    chain_1 = chain_advance(chain_0)
    chain_2 = chain_advance(chain_1)
    nonce, ct = _encrypt_at(chain_2, "three", "a", 3)
    with pytest.raises(Exception):
        _decrypt_at(chain_0, nonce, ct, "a", 3)


def test_wrong_counter_with_correct_chain_fails():
    chain_0 = os.urandom(32)
    nonce, ct = _encrypt_at(chain_0, "one", "a", 1)
    with pytest.raises(Exception):
        _decrypt_at(chain_0, nonce, ct, "a", 2)


def test_wrong_sender_with_correct_chain_fails():
    chain_0 = os.urandom(32)
    nonce, ct = _encrypt_at(chain_0, "one", "alice", 1)
    with pytest.raises(Exception):
        _decrypt_at(chain_0, nonce, ct, "bob", 1)


def test_chain_advance_irreversible():
    chain_0 = os.urandom(32)
    chain_1 = chain_advance(chain_0)
    chain_2 = chain_advance(chain_1)
    assert chain_0 != chain_1
    assert chain_1 != chain_2
    assert chain_0 != chain_2


def test_message_key_differs_per_position():
    chain_0 = os.urandom(32)
    keys = []
    for _ in range(10):
        keys.append(chain_message_key(chain_0))
        chain_0 = chain_advance(chain_0)
    assert len(set(keys)) == 10


def test_full_replay_after_chain_advanced():
    chain_a = os.urandom(32)
    chain_b = chain_a
    nonce, ct = _encrypt_at(chain_a, "replay", "a", 1)
    assert _decrypt_at(chain_b, nonce, ct, "a", 1) == "replay"
    chain_b = chain_advance(chain_b)
    with pytest.raises(Exception):
        _decrypt_at(chain_b, nonce, ct, "a", 1)


def test_padding_stable_size_across_plaintext_lengths():
    chain = os.urandom(32)
    sizes = set()
    for msg in ["a", "a" * 50, "a" * 200, "a" * 240]:
        _, ct = _encrypt_at(chain, msg, "a", 1)
        sizes.add(len(ct))
        chain = chain_advance(chain)
    assert len(sizes) == 1