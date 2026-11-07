import base64

from lanmess_files.config import CONTROL_SIG_PREFIX
from lanmess_files.crypto import generate_ed25519_private
from lanmess_files.tui import LanMessApp


class _FakeApp:
    def __init__(self, sk):
        self.ed_private = sk

    _signed = LanMessApp._signed
    _check_signed = LanMessApp._check_signed


def test_signed_has_signature():
    sk = generate_ed25519_private()
    app = _FakeApp(sk)
    signed = app._signed({"type": "TEST", "x": 1})
    assert "signature" in signed
    assert isinstance(signed["signature"], str)
    assert len(base64.b64decode(signed["signature"])) == 64


def test_signed_roundtrip_valid():
    sk = generate_ed25519_private()
    app = _FakeApp(sk)
    signed = app._signed({"type": "TEST", "a": "hello", "n": 42})
    assert app._check_signed(signed, sk.public_key())


def test_check_signed_rejects_tampered_field():
    sk = generate_ed25519_private()
    app = _FakeApp(sk)
    signed = app._signed({"type": "TEST", "x": 1})
    signed["x"] = 2
    assert not app._check_signed(signed, sk.public_key())


def test_check_signed_rejects_wrong_key():
    sk = generate_ed25519_private()
    other = generate_ed25519_private()
    app = _FakeApp(sk)
    signed = app._signed({"type": "TEST"})
    assert not app._check_signed(
        signed, other.public_key()
    )


def test_check_signed_rejects_missing_signature():
    sk = generate_ed25519_private()
    app = _FakeApp(sk)
    assert not app._check_signed(
        {"type": "TEST"}, sk.public_key()
    )


def test_check_signed_rejects_bad_base64():
    sk = generate_ed25519_private()
    app = _FakeApp(sk)
    assert not app._check_signed(
        {"type": "TEST", "signature": "not-base64!!"},
        sk.public_key(),
    )


def test_check_signed_rejects_empty_signature():
    sk = generate_ed25519_private()
    app = _FakeApp(sk)
    assert not app._check_signed(
        {"type": "TEST", "signature": ""},
        sk.public_key(),
    )


def test_signed_strips_peer_ip_from_body():
    sk = generate_ed25519_private()
    app = _FakeApp(sk)
    signed = app._signed(
        {"type": "TEST", "_peer_ip": "10.0.0.5"}
    )
    assert "_peer_ip" not in signed
    assert "signature" in signed


def test_signed_strips_existing_signature():
    sk = generate_ed25519_private()
    app = _FakeApp(sk)
    signed = app._signed(
        {"type": "TEST", "signature": "bogus"}
    )
    assert signed["signature"] != "bogus"
    assert app._check_signed(signed, sk.public_key())


def test_canonical_ordering_independent_of_key_order():
    sk = generate_ed25519_private()
    app = _FakeApp(sk)
    a = app._signed({"type": "T", "a": 1, "b": 2})
    b = app._signed({"b": 2, "a": 1, "type": "T"})
    assert app._check_signed(a, sk.public_key())
    assert app._check_signed(b, sk.public_key())


def test_control_sig_prefix_documented():
    assert CONTROL_SIG_PREFIX.endswith(b":")
    assert b"lanmess" in CONTROL_SIG_PREFIX.lower() or b"LANMESS" in CONTROL_SIG_PREFIX