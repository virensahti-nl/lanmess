import base64
import hashlib
import hmac
import json
import os
import struct
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .config import (
    ARGON2_MEMORY_COST,
    ARGON2_PARALLELISM,
    ARGON2_TIME_COST,
    AUDIT_KEY_LABEL,
    CHAIN_MSG_LABEL,
    CHAIN_NEXT_LABEL,
    GROUP_SALT,
    LOGIN_CODE_DIGITS,
    LOGIN_CODE_PERIOD,
    LOOKUP_SALT,
    PAD_BLOCK,
    PBKDF2_ITERATIONS,
    SAFETY_NUMBER_DIGITS,
    SESSION_INFO,
)

try:
    from argon2.low_level import Type as _Argon2Type
    from argon2.low_level import hash_secret_raw as _argon2_raw

    _ARGON2_OK = True
except Exception:
    _ARGON2_OK = False


def derive_group_key(group_code):
    return hashlib.pbkdf2_hmac(
        "sha256",
        group_code.encode("utf-8"),
        GROUP_SALT,
        PBKDF2_ITERATIONS,
        32,
    )


def derive_pin_key(pin, salt):
    if _ARGON2_OK:
        try:
            return _argon2_raw(
                secret=pin.encode("utf-8"),
                salt=salt,
                time_cost=ARGON2_TIME_COST,
                memory_cost=ARGON2_MEMORY_COST,
                parallelism=ARGON2_PARALLELISM,
                hash_len=32,
                type=_Argon2Type.ID,
            )
        except Exception:
            pass
    try:
        return hashlib.scrypt(
            pin.encode("utf-8"),
            salt=salt,
            n=2**16,
            r=8,
            p=1,
            maxmem=256 * 1024 * 1024,
            dklen=32,
        )
    except (ValueError, OSError):
        return hashlib.pbkdf2_hmac(
            "sha256",
            pin.encode("utf-8"),
            salt,
            2_000_000,
            32,
        )


def derive_audit_key(master):
    return hmac.new(
        master, AUDIT_KEY_LABEL, hashlib.sha256
    ).digest()


def group_key_hash(key):
    return hashlib.sha256(key).hexdigest()


def derive_lookup_key(group_key):
    return hmac.new(
        group_key, LOOKUP_SALT, hashlib.sha256
    ).digest()


def compute_name_hash(lookup_key, name):
    return hmac.new(
        lookup_key, name.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def compute_secure_code_tag(lookup_key, code):
    return hmac.new(
        lookup_key, code.encode("utf-8"), hashlib.sha256
    ).hexdigest()[:16]


def aes_gcm_encrypt(key, plaintext, nonce, aad):
    return AESGCM(key).encrypt(nonce, plaintext, aad)


def aes_gcm_decrypt(key, nonce, ct, aad):
    return AESGCM(key).decrypt(nonce, ct, aad)


def encrypt_json(key, data, aad):
    plaintext = json.dumps(
        data, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return base64.b64encode(nonce + ct).decode("ascii")


def decrypt_json(key, blob, aad):
    raw = base64.b64decode(blob)
    nonce = raw[:12]
    ct = raw[12:]
    plaintext = AESGCM(key).decrypt(nonce, ct, aad)
    return json.loads(plaintext.decode("utf-8"))


def generate_ed25519_private():
    return Ed25519PrivateKey.generate()


def ed_private_to_bytes(sk):
    return sk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def ed_public_to_bytes(pk):
    return pk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def ed_private_from_bytes(raw):
    return Ed25519PrivateKey.from_private_bytes(raw)


def ed_public_from_bytes(raw):
    return Ed25519PublicKey.from_public_bytes(raw)


def sign_bytes(sk, data):
    return sk.sign(data)


def verify_bytes(pk, sig, data):
    try:
        pk.verify(sig, data)
        return True
    except InvalidSignature:
        return False


def x25519_generate():
    return X25519PrivateKey.generate()


def x25519_private_to_bytes(sk):
    return sk.private_bytes_raw()


def x25519_public_to_bytes(pk):
    return pk.public_bytes_raw()


def x25519_private_from_bytes(raw):
    return X25519PrivateKey.from_private_bytes(raw)


def x25519_public_from_bytes(raw):
    return X25519PublicKey.from_public_bytes(raw)


def derive_session_chains(shared, eph_a_pub, eph_b_pub):
    salt = min(eph_a_pub, eph_b_pub) + max(eph_a_pub, eph_b_pub)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        info=SESSION_INFO,
    )
    return hkdf.derive(shared)


def chain_message_key(chain_key):
    return hmac.new(
        chain_key, CHAIN_MSG_LABEL, hashlib.sha256
    ).digest()


def chain_advance(chain_key):
    return hmac.new(
        chain_key, CHAIN_NEXT_LABEL, hashlib.sha256
    ).digest()


def pad_message(data):
    if len(data) > 0xFFFFFF00:
        raise ValueError("message too large")
    body = struct.pack(">I", len(data)) + data
    pad_len = (PAD_BLOCK - (len(body) % PAD_BLOCK)) % PAD_BLOCK
    return body + os.urandom(pad_len)


def unpad_message(padded):
    if len(padded) < 4:
        raise ValueError("padded payload too short")
    length = struct.unpack(">I", padded[:4])[0]
    if length > len(padded) - 4:
        raise ValueError("declared length exceeds payload")
    return padded[4:4 + length]


def compute_safety_number(ed_a_pub, ed_b_pub):
    a = ed_a_pub.hex() if isinstance(ed_a_pub, bytes) else ed_a_pub
    b = ed_b_pub.hex() if isinstance(ed_b_pub, bytes) else ed_b_pub
    if a > b:
        a, b = b, a
    digest = hashlib.sha256((a + b).encode("ascii")).digest()
    digits = "".join(f"{byte:03d}" for byte in digest)
    digits = digits[:SAFETY_NUMBER_DIGITS]
    return " ".join(
        digits[i:i + 5] for i in range(0, len(digits), 5)
    )


def generate_totp_secret():
    return os.urandom(20)


def compute_totp(secret, offset=0):
    counter = int(time.time() // LOGIN_CODE_PERIOD) + offset
    msg = struct.pack(">Q", counter)
    digest = hmac.new(secret, msg, hashlib.sha256).digest()
    off = digest[-1] & 0x0F
    code = (
        struct.unpack(">I", digest[off:off + 4])[0] & 0x7FFFFFFF
    ) % (10 ** LOGIN_CODE_DIGITS)
    return f"{code:0{LOGIN_CODE_DIGITS}d}"


def verify_totp(secret, code):
    for offset in (0, -1):
        if hmac.compare_digest(
            compute_totp(secret, offset), code
        ):
            return True
    return False


def totp_remaining():
    return LOGIN_CODE_PERIOD - int(time.time() % LOGIN_CODE_PERIOD)


def zero_bytes(buf):
    if isinstance(buf, bytearray):
        for i in range(len(buf)):
            buf[i] = 0