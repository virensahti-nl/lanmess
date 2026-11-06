import hashlib
import hmac
import json
import os
import sqlite3
import threading
import time

from .config import (
    AUDIT_AAD_PREFIX,
    AUDIT_GENESIS_HMAC,
    PIN_SALT_BYTES,
    UNREAD_MAX,
    VAULT_AAD,
    VAULT_KDF_ID,
    VAULT_VERSION,
)
from .crypto import (
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    compute_name_hash,
    decrypt_json,
    derive_audit_key,
    derive_lookup_key,
    derive_pin_key,
    encrypt_json,
    x25519_generate,
    x25519_private_to_bytes,
    x25519_public_to_bytes,
)


SCHEMA_VERSION = 6


class Database:
    def __init__(self, path):
        self.path = str(path)
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(
            self.path, check_same_thread=False
        )
        self.conn.row_factory = sqlite3.Row
        try:
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA synchronous=NORMAL")
            self.conn.execute("PRAGMA secure_delete=ON")
            self.conn.execute("PRAGMA foreign_keys=ON")
        except Exception:
            pass
        self.key = None
        self.group_key = None
        self.lookup_key = None
        self._init_schema()

    def _init_schema(self):
        with self.lock:
            self.conn.execute(
                "CREATE TABLE IF NOT EXISTS meta "
                "(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            self.conn.commit()

            version = self._get_meta("schema_version")
            if version == str(SCHEMA_VERSION):
                self._create_tables()
                return

            has_identity = self.conn.execute(
                "SELECT 1 FROM sqlite_master "
                "WHERE type='table' AND name='identity'"
            ).fetchone()

            if not has_identity:
                self._create_tables()
                self._set_meta(
                    "schema_version", str(SCHEMA_VERSION)
                )
                return

            cols = [
                r[1]
                for r in self.conn.execute(
                    "PRAGMA table_info(identity)"
                ).fetchall()
            ]

            if "data_enc" not in cols:
                self._set_meta("schema_version", "1")
            elif version in (None, "1", "2"):
                self._set_meta("schema_version", "3")
            elif version == "5":
                self._create_tables()
                self._set_meta(
                    "schema_version", str(SCHEMA_VERSION)
                )
                return

            self._create_tables()

    def _create_tables(self):
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS meta "
            "(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS identity ("
            "id INTEGER PRIMARY KEY CHECK (id = 1),"
            "data_enc TEXT NOT NULL)"
        )
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS contacts ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "name_hash TEXT UNIQUE NOT NULL,"
            "data_enc TEXT NOT NULL)"
        )
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS messages ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "contact_id INTEGER NOT NULL,"
            "data_enc TEXT NOT NULL)"
        )
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS vault ("
            "id INTEGER PRIMARY KEY CHECK (id = 1),"
            "kdf TEXT NOT NULL,"
            "salt BLOB NOT NULL,"
            "nonce BLOB NOT NULL,"
            "encrypted_master BLOB NOT NULL,"
            "version INTEGER NOT NULL)"
        )
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS audit_log ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "prev_hmac TEXT NOT NULL,"
            "own_hmac TEXT NOT NULL,"
            "data_enc TEXT NOT NULL)"
        )
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_messages_contact "
            "ON messages(contact_id, id)"
        )
        self.conn.commit()

    def _get_meta(self, key):
        with self.lock:
            try:
                row = self.conn.execute(
                    "SELECT value FROM meta WHERE key = ?",
                    (key,),
                ).fetchone()
                return row["value"] if row else None
            except sqlite3.OperationalError:
                return None

    def _set_meta(self, key, value):
        with self.lock:
            self.conn.execute(
                "CREATE TABLE IF NOT EXISTS meta "
                "(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            self.conn.execute(
                "INSERT OR REPLACE INTO meta (key, value) "
                "VALUES (?, ?)",
                (key, value),
            )
            self.conn.commit()

    def schema_version(self):
        return self._get_meta("schema_version")

    def set_schema_version(self, v):
        self._set_meta("schema_version", str(v))

    def has_identity(self):
        with self.lock:
            try:
                row = self.conn.execute(
                    "SELECT 1 FROM identity "
                    "WHERE id = 1 LIMIT 1"
                ).fetchone()
                return row is not None
            except sqlite3.OperationalError:
                return False

    def has_vault(self):
        with self.lock:
            try:
                row = self.conn.execute(
                    "SELECT 1 FROM vault "
                    "WHERE id = 1 LIMIT 1"
                ).fetchone()
                return row is not None
            except sqlite3.OperationalError:
                return False

    def get_state(self):
        with self.lock:
            if self.has_vault():
                return "needs_pin"
            if self.has_identity():
                return "needs_vault"
            return "empty"

    def setup_vault(self, master, pin):
        with self.lock:
            try:
                self.conn.execute(
                    "CREATE TABLE IF NOT EXISTS vault ("
                    "id INTEGER PRIMARY KEY CHECK (id = 1),"
                    "kdf TEXT NOT NULL,"
                    "salt BLOB NOT NULL,"
                    "nonce BLOB NOT NULL,"
                    "encrypted_master BLOB NOT NULL,"
                    "version INTEGER NOT NULL)"
                )
                self.conn.commit()
                salt = os.urandom(PIN_SALT_BYTES)
                pin_key = derive_pin_key(pin, salt)
                nonce = os.urandom(12)
                ct = aes_gcm_encrypt(
                    pin_key, master, nonce, VAULT_AAD
                )
                self.conn.execute(
                    "INSERT OR REPLACE INTO vault "
                    "(id, kdf, salt, nonce, "
                    "encrypted_master, version) "
                    "VALUES (1, ?, ?, ?, ?, ?)",
                    (
                        VAULT_KDF_ID,
                        salt,
                        nonce,
                        ct,
                        VAULT_VERSION,
                    ),
                )
                self.conn.commit()
                return True
            except Exception:
                return False

    def unlock_vault(self, pin):
        with self.lock:
            try:
                row = self.conn.execute(
                    "SELECT kdf, salt, nonce, "
                    "encrypted_master FROM vault "
                    "WHERE id = 1"
                ).fetchone()
            except sqlite3.OperationalError:
                return None
            if not row:
                return None
            try:
                pin_key = derive_pin_key(
                    pin, bytes(row["salt"])
                )
                return aes_gcm_decrypt(
                    pin_key,
                    bytes(row["nonce"]),
                    bytes(row["encrypted_master"]),
                    VAULT_AAD,
                )
            except Exception:
                return None

    def set_master(self, master):
        with self.lock:
            try:
                row = self.conn.execute(
                    "SELECT data_enc FROM identity "
                    "WHERE id = 1"
                ).fetchone()
            except sqlite3.OperationalError:
                return False
            if not row:
                return False
            try:
                data = decrypt_json(
                    master, row["data_enc"], b"identity"
                )
            except Exception:
                return False
            self.key = master
            gk = data.get("group_key_hex", "")
            if gk:
                try:
                    self.group_key = bytes.fromhex(gk)
                except ValueError:
                    return False
            else:
                self.group_key = master
            self.lookup_key = derive_lookup_key(self.group_key)
            return True

    def migrate_to_v5(self, old_master, pin):
        with self.lock:
            try:
                row = self.conn.execute(
                    "SELECT data_enc FROM identity "
                    "WHERE id = 1"
                ).fetchone()
            except sqlite3.OperationalError:
                return None
            if not row:
                return None
            try:
                old_identity = decrypt_json(
                    old_master, row["data_enc"], b"identity"
                )
            except Exception:
                return None
            new_master = os.urandom(32)
            try:
                old_identity.setdefault(
                    "group_key_hex", old_master.hex()
                )
                new_identity_enc = encrypt_json(
                    new_master, old_identity, b"identity"
                )
                contact_rows = [
                    dict(r)
                    for r in self.conn.execute(
                        "SELECT id, name_hash, data_enc "
                        "FROM contacts"
                    ).fetchall()
                ]
                message_rows = [
                    dict(r)
                    for r in self.conn.execute(
                        "SELECT id, contact_id, data_enc "
                        "FROM messages"
                    ).fetchall()
                ]
                with self.conn:
                    self.conn.execute(
                        "UPDATE identity SET data_enc = ? "
                        "WHERE id = 1",
                        (new_identity_enc,),
                    )
                    for r in contact_rows:
                        aad = (
                            b"contact:"
                            + r["name_hash"].encode()
                        )
                        try:
                            cdata = decrypt_json(
                                old_master, r["data_enc"], aad
                            )
                        except Exception:
                            return None
                        cdata.setdefault(
                            "session_local_eph_sk_hex", ""
                        )
                        cdata.setdefault(
                            "session_peer_eph_pub_hex", ""
                        )
                        cdata.setdefault(
                            "session_established", 0
                        )
                        cdata.setdefault(
                            "send_chain_key_hex", ""
                        )
                        cdata.setdefault(
                            "recv_chain_key_hex", ""
                        )
                        cdata.setdefault("send_counter", 0)
                        cdata.setdefault("recv_counter", 0)
                        cdata.setdefault("verified", 0)
                        cdata.setdefault("unread_count", 0)
                        new_ct = encrypt_json(
                            new_master, cdata, aad
                        )
                        self.conn.execute(
                            "UPDATE contacts "
                            "SET data_enc = ? WHERE id = ?",
                            (new_ct, r["id"]),
                        )
                    for r in message_rows:
                        aad = (
                            b"message:"
                            + str(r["contact_id"]).encode()
                        )
                        try:
                            mdata = decrypt_json(
                                old_master, r["data_enc"], aad
                            )
                        except Exception:
                            return None
                        new_ct = encrypt_json(
                            new_master, mdata, aad
                        )
                        self.conn.execute(
                            "UPDATE messages "
                            "SET data_enc = ? WHERE id = ?",
                            (new_ct, r["id"]),
                        )
                self.conn.execute("DELETE FROM vault")
                self.conn.commit()
            except Exception:
                return None
            if not self.setup_vault(new_master, pin):
                return None
            self.set_schema_version(SCHEMA_VERSION)
            return new_master

    def migrate_to_v3(self, group_key, from_version):
        with self.lock:
            if from_version == "1":
                row = self.conn.execute(
                    "SELECT * FROM identity WHERE id = 1"
                ).fetchone()
                if not row:
                    return False
                row_dict = dict(row)
                if "data_enc" in row_dict:
                    return True
                self._migrate_v1_to_v3(group_key)
            else:
                row = self.conn.execute(
                    "SELECT data_enc FROM identity "
                    "WHERE id = 1"
                ).fetchone()
                if not row:
                    return False
                try:
                    decrypt_json(
                        group_key,
                        row["data_enc"],
                        b"identity",
                    )
                except Exception:
                    return False
                self._migrate_v2_to_v3(group_key)
            return True

    def _migrate_v1_to_v3(self, group_key):
        lookup_key = derive_lookup_key(group_key)
        identity_row = dict(
            self.conn.execute(
                "SELECT * FROM identity WHERE id = 1"
            ).fetchone()
        )
        contacts_rows = [
            dict(r)
            for r in self.conn.execute(
                "SELECT * FROM contacts"
            ).fetchall()
        ]
        messages_rows = [
            dict(r)
            for r in self.conn.execute(
                "SELECT * FROM messages"
            ).fetchall()
        ]

        with self.conn:
            self.conn.execute(
                "CREATE TABLE identity_v3 ("
                "id INTEGER PRIMARY KEY CHECK (id = 1),"
                "data_enc TEXT NOT NULL)"
            )
            self.conn.execute(
                "CREATE TABLE contacts_v3 ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "name_hash TEXT UNIQUE NOT NULL,"
                "data_enc TEXT NOT NULL)"
            )
            self.conn.execute(
                "CREATE TABLE messages_v3 ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "contact_id INTEGER NOT NULL,"
                "data_enc TEXT NOT NULL)"
            )

            x_sk = x25519_generate()
            identity_data = {
                "name": identity_row["name"],
                "ed_private_hex": identity_row[
                    "ed_private_hex"
                ],
                "ed_public_hex": identity_row[
                    "ed_public_hex"
                ],
                "totp_secret_hex": identity_row[
                    "totp_secret_hex"
                ],
                "tcp_port": int(identity_row["tcp_port"]),
                "x25519_private_hex": (
                    x25519_private_to_bytes(x_sk).hex()
                ),
                "x25519_public_hex": (
                    x25519_public_to_bytes(
                        x_sk.public_key()
                    ).hex()
                ),
                "group_key_hex": group_key.hex(),
            }
            identity_enc = encrypt_json(
                group_key, identity_data, b"identity"
            )
            self.conn.execute(
                "INSERT INTO identity_v3 (id, data_enc) "
                "VALUES (1, ?)",
                (identity_enc,),
            )

            name_to_id = {}
            for c in contacts_rows:
                name = c["name"]
                name_hash = compute_name_hash(
                    lookup_key, name
                )
                contact_data = {
                    "name": name,
                    "ip": c.get("ip"),
                    "port": c.get("port"),
                    "ed_public_hex": c["ed_public_hex"],
                    "x25519_public_hex": "",
                    "chat_started": int(
                        c.get("chat_started", 0)
                    ),
                    "incoming_request": int(
                        c.get("incoming_request", 0)
                    ),
                    "blocked": int(
                        c.get("blocked", 0)
                    ),
                    "pending": int(
                        c.get("pending", 0)
                    ),
                    "clear_pending": int(
                        c.get("clear_pending", 0)
                    ),
                    "out_counter": 0,
                    "last_counter_in": 0,
                    "session_local_eph_sk_hex": "",
                    "session_peer_eph_pub_hex": "",
                    "session_established": 0,
                    "send_chain_key_hex": "",
                    "recv_chain_key_hex": "",
                    "send_counter": 0,
                    "recv_counter": 0,
                    "verified": 0,
                    "unread_count": 0,
                    "added_at": float(
                        c.get("added_at", time.time())
                    ),
                }
                aad = b"contact:" + name_hash.encode()
                data_enc = encrypt_json(
                    group_key, contact_data, aad
                )
                cur = self.conn.execute(
                    "INSERT INTO contacts_v3 "
                    "(name_hash, data_enc) VALUES (?, ?)",
                    (name_hash, data_enc),
                )
                name_to_id[name] = cur.lastrowid

            for m in messages_rows:
                contact_id = name_to_id.get(m["contact_name"])
                if not contact_id:
                    continue
                msg_data = {
                    "direction": m["direction"],
                    "content": m["content"],
                    "timestamp": float(m["timestamp"]),
                }
                aad = (
                    b"message:" + str(contact_id).encode()
                )
                data_enc = encrypt_json(
                    group_key, msg_data, aad
                )
                self.conn.execute(
                    "INSERT INTO messages_v3 "
                    "(contact_id, data_enc) VALUES (?, ?)",
                    (contact_id, data_enc),
                )

            self.conn.execute("DROP TABLE messages")
            self.conn.execute("DROP TABLE contacts")
            self.conn.execute("DROP TABLE identity")
            self.conn.execute(
                "ALTER TABLE identity_v3 RENAME TO identity"
            )
            self.conn.execute(
                "ALTER TABLE contacts_v3 RENAME TO contacts"
            )
            self.conn.execute(
                "ALTER TABLE messages_v3 RENAME TO messages"
            )
            self.conn.execute(
                "CREATE INDEX idx_messages_contact "
                "ON messages(contact_id, id)"
            )

    def _migrate_v2_to_v3(self, group_key):
        lookup_key = derive_lookup_key(group_key)
        identity_row = self.conn.execute(
            "SELECT data_enc FROM identity WHERE id = 1"
        ).fetchone()
        identity_data = decrypt_json(
            group_key, identity_row["data_enc"], b"identity"
        )
        x_sk = x25519_generate()
        identity_data["x25519_private_hex"] = (
            x25519_private_to_bytes(x_sk).hex()
        )
        identity_data["x25519_public_hex"] = (
            x25519_public_to_bytes(x_sk.public_key()).hex()
        )
        identity_data.setdefault(
            "group_key_hex", group_key.hex()
        )
        identity_enc = encrypt_json(
            group_key, identity_data, b"identity"
        )

        contact_rows = [
            dict(r)
            for r in self.conn.execute(
                "SELECT id, name_hash, data_enc FROM contacts"
            ).fetchall()
        ]

        with self.conn:
            self.conn.execute(
                "UPDATE identity SET data_enc = ? "
                "WHERE id = 1",
                (identity_enc,),
            )
            for r in contact_rows:
                aad = (
                    b"contact:" + r["name_hash"].encode()
                )
                try:
                    cdata = decrypt_json(
                        group_key, r["data_enc"], aad
                    )
                except Exception:
                    continue
                cdata.setdefault("x25519_public_hex", "")
                cdata.setdefault("out_counter", 0)
                cdata.setdefault("last_counter_in", 0)
                cdata.setdefault("session_local_eph_sk_hex", "")
                cdata.setdefault("session_peer_eph_pub_hex", "")
                cdata.setdefault("session_established", 0)
                cdata.setdefault("send_chain_key_hex", "")
                cdata.setdefault("recv_chain_key_hex", "")
                cdata.setdefault("send_counter", 0)
                cdata.setdefault("recv_counter", 0)
                cdata.setdefault("verified", 0)
                cdata.setdefault("unread_count", 0)
                new_enc = encrypt_json(
                    group_key, cdata, aad
                )
                self.conn.execute(
                    "UPDATE contacts SET data_enc = ? "
                    "WHERE id = ?",
                    (new_enc, r["id"]),
                )

    def create_identity(
        self,
        name,
        master,
        group_key,
        ed_private_hex,
        ed_public_hex,
        totp_secret_hex,
        tcp_port,
        x25519_private_hex,
        x25519_public_hex,
    ):
        with self.lock:
            self._set_meta(
                "schema_version", str(SCHEMA_VERSION)
            )
            self.key = master
            self.group_key = group_key
            self.lookup_key = derive_lookup_key(group_key)
            data = {
                "name": name,
                "ed_private_hex": ed_private_hex,
                "ed_public_hex": ed_public_hex,
                "totp_secret_hex": totp_secret_hex,
                "tcp_port": int(tcp_port),
                "x25519_private_hex": x25519_private_hex,
                "x25519_public_hex": x25519_public_hex,
                "group_key_hex": group_key.hex(),
            }
            enc = encrypt_json(master, data, b"identity")
            self.conn.execute(
                "INSERT OR REPLACE INTO identity "
                "(id, data_enc) VALUES (1, ?)",
                (enc,),
            )
            self.conn.commit()

    def get_identity(self):
        with self.lock:
            if self.key is None:
                return None
            try:
                row = self.conn.execute(
                    "SELECT data_enc FROM identity "
                    "WHERE id = 1"
                ).fetchone()
            except sqlite3.OperationalError:
                return None
            if not row:
                return None
            try:
                return decrypt_json(
                    self.key, row["data_enc"], b"identity"
                )
            except Exception:
                return None

    def update_tcp_port(self, port):
        with self.lock:
            if self.key is None:
                return
            row = self.conn.execute(
                "SELECT data_enc FROM identity "
                "WHERE id = 1"
            ).fetchone()
            if not row:
                return
            try:
                data = decrypt_json(
                    self.key, row["data_enc"], b"identity"
                )
            except Exception:
                return
            data["tcp_port"] = int(port)
            enc = encrypt_json(
                self.key, data, b"identity"
            )
            self.conn.execute(
                "UPDATE identity SET data_enc = ? "
                "WHERE id = 1",
                (enc,),
            )
            self.conn.commit()

    def _name_hash(self, name):
        return compute_name_hash(self.lookup_key, name)

    def get_contacts(self):
        with self.lock:
            if self.key is None or self.lookup_key is None:
                return []
            result = []
            for row in self.conn.execute(
                "SELECT id, name_hash, data_enc FROM contacts"
            ):
                try:
                    data = decrypt_json(
                        self.key,
                        row["data_enc"],
                        b"contact:"
                        + row["name_hash"].encode(),
                    )
                    data["_id"] = row["id"]
                    data["unread_count"] = int(
                        data.get("unread_count", 0)
                    )
                    result.append(data)
                except Exception:
                    continue
            result.sort(key=lambda c: c.get("name", ""))
            return result

    def get_contact(self, name):
        with self.lock:
            if (
                not name
                or self.key is None
                or self.lookup_key is None
            ):
                return None
            name_hash = self._name_hash(name)
            row = self.conn.execute(
                "SELECT id, data_enc FROM contacts "
                "WHERE name_hash = ?",
                (name_hash,),
            ).fetchone()
            if not row:
                return None
            try:
                data = decrypt_json(
                    self.key,
                    row["data_enc"],
                    b"contact:" + name_hash.encode(),
                )
                data["_id"] = row["id"]
                data["unread_count"] = int(
                    data.get("unread_count", 0)
                )
                return data
            except Exception:
                return None

    def upsert_contact(
        self,
        name,
        ip,
        port,
        ed_public_hex,
        x25519_public_hex=None,
    ):
        with self.lock:
            if (
                not name
                or self.key is None
                or self.lookup_key is None
            ):
                return
            name_hash = self._name_hash(name)
            aad = b"contact:" + name_hash.encode()
            row = self.conn.execute(
                "SELECT id, data_enc FROM contacts "
                "WHERE name_hash = ?",
                (name_hash,),
            ).fetchone()
            if row:
                try:
                    data = decrypt_json(
                        self.key, row["data_enc"], aad
                    )
                except Exception:
                    return
                data["ip"] = ip
                data["port"] = port
                data["ed_public_hex"] = ed_public_hex
                if x25519_public_hex is not None:
                    data["x25519_public_hex"] = x25519_public_hex
                data["added_at"] = time.time()
                enc = encrypt_json(self.key, data, aad)
                self.conn.execute(
                    "UPDATE contacts SET data_enc = ? "
                    "WHERE id = ?",
                    (enc, row["id"]),
                )
            else:
                data = {
                    "name": name,
                    "ip": ip,
                    "port": port,
                    "ed_public_hex": ed_public_hex,
                    "x25519_public_hex": (
                        x25519_public_hex or ""
                    ),
                    "chat_started": 0,
                    "incoming_request": 0,
                    "blocked": 0,
                    "pending": 0,
                    "clear_pending": 0,
                    "out_counter": 0,
                    "last_counter_in": 0,
                    "session_local_eph_sk_hex": "",
                    "session_peer_eph_pub_hex": "",
                    "session_established": 0,
                    "send_chain_key_hex": "",
                    "recv_chain_key_hex": "",
                    "send_counter": 0,
                    "recv_counter": 0,
                    "verified": 0,
                    "unread_count": 0,
                    "added_at": time.time(),
                }
                enc = encrypt_json(self.key, data, aad)
                self.conn.execute(
                    "INSERT INTO contacts "
                    "(name_hash, data_enc) VALUES (?, ?)",
                    (name_hash, enc),
                )
            self.conn.commit()

    def set_contact_state(self, name, **kwargs):
        with self.lock:
            if (
                not name
                or self.key is None
                or self.lookup_key is None
            ):
                return
            name_hash = self._name_hash(name)
            aad = b"contact:" + name_hash.encode()
            row = self.conn.execute(
                "SELECT id, data_enc FROM contacts "
                "WHERE name_hash = ?",
                (name_hash,),
            ).fetchone()
            if not row:
                return
            try:
                data = decrypt_json(
                    self.key, row["data_enc"], aad
                )
            except Exception:
                return
            int_fields = {
                "chat_started",
                "incoming_request",
                "blocked",
                "pending",
                "clear_pending",
                "out_counter",
                "last_counter_in",
                "session_established",
                "send_counter",
                "recv_counter",
                "verified",
                "unread_count",
            }
            for k in kwargs:
                v = kwargs[k]
                if v is None:
                    continue
                data[k] = int(v) if k in int_fields else v
            enc = encrypt_json(self.key, data, aad)
            self.conn.execute(
                "UPDATE contacts SET data_enc = ? "
                "WHERE id = ?",
                (enc, row["id"]),
            )
            self.conn.commit()

    def increment_unread(self, name):
        contact = self.get_contact(name)
        if not contact:
            return
        current = int(contact.get("unread_count", 0))
        new_val = min(current + 1, UNREAD_MAX)
        if new_val != current:
            self.set_contact_state(name, unread_count=new_val)

    def clear_unread(self, name):
        contact = self.get_contact(name)
        if not contact:
            return
        if int(contact.get("unread_count", 0)) != 0:
            self.set_contact_state(name, unread_count=0)

    def total_unread(self):
        return sum(
            int(c.get("unread_count", 0))
            for c in self.get_contacts()
        )

    def _last_audit_hmac(self):
        try:
            row = self.conn.execute(
                "SELECT own_hmac FROM audit_log "
                "ORDER BY id DESC LIMIT 1"
            ).fetchone()
        except sqlite3.OperationalError:
            return AUDIT_GENESIS_HMAC
        return row["own_hmac"] if row else AUDIT_GENESIS_HMAC

    def append_audit(self, event_type, detail=None):
        with self.lock:
            if self.key is None:
                return False
            try:
                prev_hmac = self._last_audit_hmac()
                entry = {
                    "type": str(event_type),
                    "detail": detail or {},
                    "ts": time.time(),
                }
                audit_key = derive_audit_key(self.key)
                msg = json.dumps(
                    entry,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
                hmac_val = hmac.new(
                    audit_key,
                    msg + prev_hmac.encode("utf-8"),
                    hashlib.sha256,
                ).hexdigest()
                aad = AUDIT_AAD_PREFIX + prev_hmac.encode(
                    "utf-8"
                )
                payload = {**entry, "hmac": hmac_val}
                enc = encrypt_json(self.key, payload, aad)
                self.conn.execute(
                    "INSERT INTO audit_log "
                    "(prev_hmac, own_hmac, data_enc) "
                    "VALUES (?, ?, ?)",
                    (prev_hmac, hmac_val, enc),
                )
                self.conn.commit()
                return True
            except Exception:
                return False

    def verify_audit_chain(self):
        with self.lock:
            if self.key is None:
                return False
            try:
                audit_key = derive_audit_key(self.key)
                expected_prev = AUDIT_GENESIS_HMAC
                for row in self.conn.execute(
                    "SELECT id, prev_hmac, own_hmac, data_enc "
                    "FROM audit_log ORDER BY id"
                ):
                    if not hmac.compare_digest(
                        row["prev_hmac"], expected_prev
                    ):
                        return False
                    aad = AUDIT_AAD_PREFIX + row[
                        "prev_hmac"
                    ].encode("utf-8")
                    try:
                        payload = decrypt_json(
                            self.key, row["data_enc"], aad
                        )
                    except Exception:
                        return False
                    entry = {
                        k: payload[k]
                        for k in ("type", "detail", "ts")
                        if k in payload
                    }
                    msg = json.dumps(
                        entry,
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8")
                    expected_hmac = hmac.new(
                        audit_key,
                        msg
                        + row["prev_hmac"].encode("utf-8"),
                        hashlib.sha256,
                    ).hexdigest()
                    if not hmac.compare_digest(
                        expected_hmac, row["own_hmac"]
                    ):
                        return False
                    expected_prev = row["own_hmac"]
                return True
            except Exception:
                return False

    def _contact_id(self, name):
        if not name or self.lookup_key is None:
            return None
        name_hash = self._name_hash(name)
        row = self.conn.execute(
            "SELECT id FROM contacts WHERE name_hash = ?",
            (name_hash,),
        ).fetchone()
        return row["id"] if row else None

    def add_message(self, contact_name, direction, content):
        with self.lock:
            if self.key is None:
                return
            contact_id = self._contact_id(contact_name)
            if not contact_id:
                return
            data = {
                "direction": direction,
                "content": content,
                "timestamp": time.time(),
            }
            aad = b"message:" + str(contact_id).encode()
            enc = encrypt_json(self.key, data, aad)
            self.conn.execute(
                "INSERT INTO messages (contact_id, data_enc) "
                "VALUES (?, ?)",
                (contact_id, enc),
            )
            self.conn.commit()

    def get_messages(self, contact_name, limit=500):
        with self.lock:
            if self.key is None or not contact_name:
                return []
            contact_id = self._contact_id(contact_name)
            if not contact_id:
                return []
            aad = b"message:" + str(contact_id).encode()
            results = []
            for r in self.conn.execute(
                "SELECT id, data_enc FROM messages "
                "WHERE contact_id = ? "
                "ORDER BY id DESC LIMIT ?",
                (contact_id, limit),
            ):
                try:
                    data = decrypt_json(
                        self.key, r["data_enc"], aad
                    )
                    data["id"] = r["id"]
                    data["contact_name"] = contact_name
                    results.append(data)
                except Exception:
                    continue
            return list(reversed(results))

    def clear_messages(self, contact_name):
        with self.lock:
            contact_id = self._contact_id(contact_name)
            if not contact_id:
                return
            self.conn.execute(
                "DELETE FROM messages WHERE contact_id = ?",
                (contact_id,),
            )
            self.conn.commit()
        self.clear_unread(contact_name)

    def delete_message(self, message_id):
        with self.lock:
            self.conn.execute(
                "DELETE FROM messages WHERE id = ?",
                (message_id,),
            )
            self.conn.commit()

    def delete_contact(self, contact_name):
        with self.lock:
            contact_id = self._contact_id(contact_name)
            if not contact_id:
                return
            self.conn.execute(
                "DELETE FROM messages WHERE contact_id = ?",
                (contact_id,),
            )
            self.conn.execute(
                "DELETE FROM contacts WHERE id = ?",
                (contact_id,),
            )
            self.conn.commit()

    def reset_all(self):
        with self.lock:
            try:
                self.conn.execute(
                    "DROP TABLE IF EXISTS messages"
                )
                self.conn.execute(
                    "DROP TABLE IF EXISTS contacts"
                )
                self.conn.execute(
                    "DROP TABLE IF EXISTS identity"
                )
                self.conn.execute(
                    "DROP TABLE IF EXISTS vault"
                )
                self.conn.execute(
                    "DROP TABLE IF EXISTS audit_log"
                )
                self.conn.execute(
                    "DROP TABLE IF EXISTS meta"
                )
                self.conn.commit()
            except Exception:
                pass
            self._create_tables()
            self._set_meta(
                "schema_version", str(SCHEMA_VERSION)
            )
            self.key = None
            self.group_key = None
            self.lookup_key = None
            try:
                self.conn.execute("VACUUM")
            except Exception:
                pass

    def close(self):
        with self.lock:
            try:
                self.conn.close()
            except Exception:
                pass