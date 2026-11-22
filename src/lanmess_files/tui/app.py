import asyncio
import base64
import hashlib
import hmac
import json
import os
import signal
import socket
import time

import lanmess_files.tui as _tui

from textual.app import App

from ..config import (
    APP_NAME,
    APP_VERSION,
    CONTROL_SIG_PREFIX,
    DB_PATH,
    MAX_MESSAGE_LEN,
    MESSAGE_TIMEOUT,
    OUTBOX_RETRY_INTERVAL,
    PRESENCE_INTERVAL,
    PROBE_TIMEOUT,
    REPLAY_WINDOW_SECONDS,
    SEARCH_WAIT_SECONDS,
    SESSION_IDLE_TIMEOUT,
    STOP_TIMEOUT,
    TCP_PORT_RANGE,
    TYPING_THROTTLE,
    ensure_dirs,
)
from ..crypto import (
    aes_gcm_encrypt,
    chain_advance,
    chain_message_key,
    compute_safety_number,
    compute_secure_code_tag,
    compute_totp,
    derive_group_key,
    derive_lookup_key,
    derive_session_chains,
    ed_private_from_bytes,
    ed_private_to_bytes,
    ed_public_from_bytes,
    ed_public_to_bytes,
    generate_ed25519_private,
    generate_totp_secret,
    pad_message,
    sign_bytes,
    verify_bytes,
    x25519_generate,
    x25519_private_from_bytes,
    x25519_private_to_bytes,
    x25519_public_from_bytes,
    x25519_public_to_bytes,
)
from ..database import Database
from ..discovery import Discovery
from ..network import Server
from .app_handlers import HandlersMixin
from .helpers import (
    _check_pin_strength,
    _now_ms,
)
from .main_screen import MainScreen
from .screens import (
    ConfirmScreen,
    StartupScreen,
    VerifyScreen,
)


async def send_request(*args, **kwargs):
    return await _tui.send_request(*args, **kwargs)


class LanMessApp(HandlersMixin, App):
    TITLE = f"{APP_NAME} {APP_VERSION}"
    CSS = """
    Screen { background: $surface; }
    """

    def __init__(self):
        super().__init__()
        ensure_dirs()
        self.db = Database(DB_PATH)
        self.discovery = Discovery()
        self.server = None
        self.broadcast_task = None
        self.idle_task = None
        self.presence_task = None
        self.outbox_task = None
        self.group_key = None
        self.lookup_key = None
        self.totp_secret = None
        self.ed_private = None
        self.ed_public = None
        self.x25519_private = None
        self.x25519_public = None
        self.user_name = None
        self.tcp_port = None
        self._add_attempts = {}
        self._name_attempts = {}
        self._msg_attempts = {}
        self._contact_locks = {}
        self._peer_typing = {}
        self._last_activity = {}
        self._last_heard = {}
        self._peer_offline = {}
        self._presence_success = {}
        self._presence_fail = {}
        self._last_typing_sent = {}
        self._outbox = {}
        self._pending_rotates = {}
        self._global_last_activity = time.time()
        self._auto_lock_in_progress = False

    def on_mount(self):
        self.push_screen(StartupScreen(self.db))
        try:
            loop = asyncio.get_event_loop()
            for sig in (signal.SIGINT, signal.SIGTERM):
                try:
                    loop.add_signal_handler(
                        sig, self._signal_shutdown
                    )
                except (
                    NotImplementedError,
                    RuntimeError,
                ):
                    pass
        except Exception:
            pass

    def _signal_shutdown(self):
        asyncio.create_task(self._graceful_shutdown())

    async def _graceful_shutdown(self):
        try:
            await self.broadcast_offline_now()
        except Exception:
            pass
        try:
            await self._stop_networking()
        except Exception:
            pass
        self._zero_keys()
        self.exit()

    async def _on_exit(self):
        try:
            await self._stop_networking()
        except Exception:
            pass
        self._zero_keys()

    def _zero_keys(self):
        for attr in (
            "group_key",
            "lookup_key",
            "totp_secret",
            "ed_private",
            "ed_public",
            "x25519_private",
            "x25519_public",
        ):
            try:
                setattr(self, attr, None)
            except Exception:
                pass
        try:
            self.db.key = None
            self.db.group_key = None
            self.db.lookup_key = None
        except Exception:
            pass

    def _valid_name(self, s):
        if not isinstance(s, str) or not (1 <= len(s) <= 40):
            return False
        return not any(ord(c) < 32 for c in s)

    def _valid_hex(self, s, nbytes):
        if not isinstance(s, str):
            return False
        if len(s) != nbytes * 2:
            return False
        for c in s:
            if c not in "0123456789abcdefABCDEF":
                return False
        return True

    def _valid_code(self, s):
        return (
            isinstance(s, str)
            and len(s) == 8
            and s.isdigit()
        )

    def _valid_timestamp(self, ts):
        if not isinstance(ts, int) or ts <= 0:
            return False
        return (
            abs(_now_ms() - ts)
            <= REPLAY_WINDOW_SECONDS * 1000
        )

    def _resolve_peer_address(self, contact):
        peer = self.discovery.find_by_name(contact["name"])
        if peer:
            return peer["ip"], peer["tcp_port"]
        if contact.get("ip") and contact.get("port"):
            return contact["ip"], int(contact["port"])
        return None, None

    def _get_contact_lock(self, name):
        if name not in self._contact_locks:
            self._contact_locks[name] = asyncio.Lock()
        return self._contact_locks[name]

    def _signed(self, fields):
        body = {
            k: v
            for k, v in fields.items()
            if k not in ("signature", "_peer_ip")
        }
        data = CONTROL_SIG_PREFIX + json.dumps(
            body, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        sig = base64.b64encode(
            sign_bytes(self.ed_private, data)
        ).decode("ascii")
        return {**body, "signature": sig}

    def _check_signed(self, msg, peer_pub):
        sig_b64 = msg.get("signature")
        if not isinstance(sig_b64, str):
            return False
        try:
            sig = base64.b64decode(sig_b64)
        except Exception:
            return False
        body = {
            k: v
            for k, v in msg.items()
            if k not in ("signature", "_peer_ip")
        }
        data = CONTROL_SIG_PREFIX + json.dumps(
            body, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        return verify_bytes(peer_pub, sig, data)

    def _prune_dict(self, d, cap):
        if len(d) > cap:
            d.clear()

    def _is_currently_viewing(self, contact_name):
        if not isinstance(self.screen, MainScreen):
            return False
        return self.screen.current_contact == contact_name

    def _audit(self, event_type, detail=None):
        try:
            self.db.append_audit(event_type, detail or {})
        except Exception:
            pass

    def _apply_peer_ip(self, msg, name):
        peer_ip = msg.get("_peer_ip")
        if not peer_ip:
            return
        contact = self.db.get_contact(name)
        if not contact:
            return
        if contact.get("ip") == peer_ip:
            return
        if contact.get("pinned"):
            return
        self.db.set_contact_state(name, ip=peer_ip)

    def _touch_activity(self, name):
        self._last_activity[name] = time.time()
        self._global_last_activity = time.time()

    def _touch_heard(self, name):
        self._last_heard[name] = time.time()
        self._peer_offline.pop(name, None)
        self._presence_fail.pop(name, None)

    def _mark_offline(self, name):
        self._peer_offline[name] = time.time()
        self._last_heard[name] = 0
        self._presence_success.pop(name, None)

    def _record_probe_success(self, name):
        succ = self._presence_success.get(name, 0) + 1
        self._presence_success[name] = succ
        if succ >= 2:
            self._touch_heard(name)
            self._refresh_main()
            self._check_auto_reconnect(name)

    def _record_probe_failure(self, name):
        fail = self._presence_fail.get(name, 0) + 1
        self._presence_fail[name] = fail
        if fail >= 2:
            self._mark_offline(name)
            self._refresh_main()

    def _check_auto_reconnect(self, name):
        contact = self.db.get_contact(name)
        if not contact:
            return
        if contact.get("chat_started") and not contact.get(
            "session_established"
        ):
            asyncio.create_task(self.start_chat(name))

    def _get_current_pub_keys(self):
        return (
            ed_public_to_bytes(self.ed_public).hex(),
            x25519_public_to_bytes(self.x25519_public).hex(),
        )

    def _is_blocked(self, name):
        if not name:
            return False
        if self.db.is_blocked(name):
            return True
        contact = self.db.get_contact(name)
        if contact and contact.get("blocked"):
            return True
        return False

    def _should_auto_lock(self, now=None):
        if now is None:
            now = time.time()
        try:
            seconds = self.db.get_auto_lock_seconds()
        except Exception:
            return False
        if seconds <= 0:
            return False
        if not self.user_name:
            return False
        last = getattr(self, "_global_last_activity", now)
        return (now - last) > seconds

    async def create_identity(self, name, group_code, pin):
        group_key = await asyncio.to_thread(
            derive_group_key, group_code
        )
        master = os.urandom(32)
        sk_ed = generate_ed25519_private()
        pk_ed = sk_ed.public_key()
        sk_x = x25519_generate()
        pk_x = sk_x.public_key()
        totp = generate_totp_secret()
        port = self._find_free_port()
        self.db.create_identity(
            name=name,
            master=master,
            group_key=group_key,
            ed_private_hex=ed_private_to_bytes(sk_ed).hex(),
            ed_public_hex=ed_public_to_bytes(pk_ed).hex(),
            totp_secret_hex=totp.hex(),
            tcp_port=port,
            x25519_private_hex=(
                x25519_private_to_bytes(sk_x).hex()
            ),
            x25519_public_hex=(
                x25519_public_to_bytes(pk_x).hex()
            ),
        )
        ok = await asyncio.to_thread(
            self.db.setup_vault, master, pin
        )
        if not ok:
            self.notify(
                "Failed to create vault.",
                severity="error",
            )
            return
        self.db.set_schema_version(10)
        await self._start_session()
        self._audit("IDENTITY_CREATED", {"name": name})

    async def migrate_needs_vault(self, group_code, pin):
        group_key = await asyncio.to_thread(
            derive_group_key, group_code
        )
        version = self.db.schema_version()
        if version in ("1", "2"):
            ok = await asyncio.to_thread(
                self.db.migrate_to_v3, group_key, version
            )
            if not ok:
                return False
            self.db.set_schema_version(3)
            version = "3"
        if version in ("3", "4"):
            ok = await asyncio.to_thread(
                self.db.set_master, group_key
            )
            if not ok:
                return False
            new_master = await asyncio.to_thread(
                self.db.migrate_to_v5, group_key, pin
            )
            if new_master is None:
                return False
            ok = await asyncio.to_thread(
                self.db.set_master, new_master
            )
            if not ok:
                return False
            await self._start_session()
            self._audit("MIGRATED_TO_V10")
            return True
        return False

    async def unlock(self, pin):
        remaining = self.db.lockout_remaining()
        if remaining > 0:
            self.notify(
                f"Too many failed attempts. "
                f"Try again in {int(remaining)}s.",
                severity="error",
            )
            return False
        master = await asyncio.to_thread(
            self.db.unlock_vault, pin
        )
        if master is None:
            lockout = self.db.record_pin_failure()
            if lockout > 0:
                rem = int(lockout - time.time())
                self.notify(
                    f"PIN incorrect. Locked out "
                    f"for {rem}s.",
                    severity="error",
                )
            return False
        self.db.record_pin_success()
        version = self.db.schema_version()
        if version == "4":
            new_master = await asyncio.to_thread(
                self.db.migrate_to_v5, master, pin
            )
            if new_master is None:
                return False
            master = new_master
        ok = await asyncio.to_thread(
            self.db.set_master, master
        )
        if not ok:
            return False
        if self.db._get_meta("panic_pin_reset") == "1":
            self.notify(
                "Panic PIN was reset during upgrade. "
                "Please set a new one from the menu.",
                severity="warning",
                timeout=8,
            )
            self.db._set_meta("panic_pin_reset", "")
        await self._start_session()
        return True

    async def change_pin(self, old_pin, new_pin):
        if self.db.key is None:
            return False
        err = _check_pin_strength(new_pin)
        if err:
            return False
        current = await asyncio.to_thread(
            self.db.unlock_vault, old_pin
        )
        if current is None:
            return False
        if current != self.db.key:
            return False
        ok = await asyncio.to_thread(
            self.db.setup_vault, self.db.key, new_pin
        )
        if not ok:
            return False
        self._audit("PIN_CHANGED")
        return True

    async def panic_wipe(self):
        try:
            await self._stop_networking()
        except Exception:
            pass
        try:
            self.db.reset_all()
        except Exception:
            pass
        try:
            self.db.close()
        except Exception:
            pass
        self._zero_keys()
        try:
            if DB_PATH.exists():
                DB_PATH.unlink()
            for suffix in ("-wal", "-shm", "-journal"):
                p = DB_PATH.with_name(DB_PATH.name + suffix)
                if p.exists():
                    p.unlink()
        except Exception:
            pass
        self.exit()

    async def lock(self):
        self._audit("LOCKED")
        try:
            await self.broadcast_offline_now()
        except Exception:
            pass
        await self._stop_networking()
        self._zero_keys()
        self.user_name = None
        self.tcp_port = None
        self._add_attempts = {}
        self._name_attempts = {}
        self._msg_attempts = {}
        self._contact_locks = {}
        self._peer_typing = {}
        self._last_activity = {}
        self._last_heard = {}
        self._peer_offline = {}
        self._presence_success = {}
        self._presence_fail = {}
        self._last_typing_sent = {}
        self._outbox = {}
        self._pending_rotates = {}
        self._auto_lock_in_progress = False
        while len(self.screen_stack) > 1:
            self.pop_screen()
        self.push_screen(StartupScreen(self.db))
        self.notify("Locked.")

    def _find_free_port(self):
        for port in range(
            TCP_PORT_RANGE[0], TCP_PORT_RANGE[1]
        ):
            s = socket.socket(
                socket.AF_INET, socket.SOCK_STREAM
            )
            try:
                s.bind(("0.0.0.0", port))
                s.close()
                return port
            except OSError:
                try:
                    s.close()
                except Exception:
                    pass
        raise RuntimeError("No free TCP port available")

    async def _stop_networking(self):
        if self.server is not None:
            try:
                await self.server.stop()
            except Exception:
                pass
            self.server = None
        for task_attr in (
            "broadcast_task",
            "idle_task",
            "presence_task",
            "outbox_task",
        ):
            task = getattr(self, task_attr, None)
            if task is not None:
                try:
                    task.cancel()
                    try:
                        await task
                    except (
                        asyncio.CancelledError,
                        Exception,
                    ):
                        pass
                except Exception:
                    pass
                setattr(self, task_attr, None)
        try:
            await self.discovery.stop()
        except Exception:
            pass

    async def _start_session(self):
        try:
            await self._stop_networking()
            identity = self.db.get_identity()
            if not identity:
                raise RuntimeError("No identity found")
            self.user_name = identity["name"]
            self.group_key = self.db.group_key
            self.lookup_key = derive_lookup_key(
                self.group_key
            )
            self.totp_secret = bytes.fromhex(
                identity["totp_secret_hex"]
            )
            self.ed_private = ed_private_from_bytes(
                bytes.fromhex(identity["ed_private_hex"])
            )
            self.ed_public = ed_public_from_bytes(
                bytes.fromhex(identity["ed_public_hex"])
            )
            self.x25519_private = x25519_private_from_bytes(
                bytes.fromhex(
                    identity["x25519_private_hex"]
                )
            )
            self.x25519_public = x25519_public_from_bytes(
                bytes.fromhex(
                    identity["x25519_public_hex"]
                )
            )
            self._last_heard = {}
            self._peer_offline = {}
            self._peer_typing = {}
            self._presence_success = {}
            self._presence_fail = {}
            self._last_activity = {}
            self._last_typing_sent = {}
            self._name_attempts = {}
            try:
                self._pending_rotates = self.db.load_pending_rotates()
            except Exception:
                self._pending_rotates = {}
            self._global_last_activity = time.time()
            self._auto_lock_in_progress = False
            self.tcp_port = int(identity["tcp_port"])
            self.server = Server(
                self.tcp_port, self.handle_incoming
            )
            try:
                await self.server.start()
            except OSError:
                new_port = self._find_free_port()
                self.db.update_tcp_port(new_port)
                self.tcp_port = new_port
                self.server = Server(
                    self.tcp_port, self.handle_incoming
                )
                await self.server.start()
            await self.discovery.start()
            self.broadcast_task = asyncio.create_task(
                self.discovery.broadcaster(
                    self.user_name,
                    self.tcp_port,
                    self._get_current_pub_keys,
                    self._current_code_tags,
                )
            )
            self.idle_task = asyncio.create_task(
                self._idle_watchdog()
            )
            self.presence_task = asyncio.create_task(
                self._presence_loop()
            )
            self.outbox_task = asyncio.create_task(
                self._outbox_loop()
            )
            self.push_screen(MainScreen())
            asyncio.create_task(
                self.broadcast_presence_now()
            )
        except Exception as exc:
            self.notify(
                f"Startup error: {exc}", severity="error"
            )

    async def _idle_watchdog(self):
        while True:
            try:
                await asyncio.sleep(30)
                now = time.time()
                if (
                    self.user_name
                    and not self._auto_lock_in_progress
                    and self._should_auto_lock(now)
                ):
                    self._auto_lock_in_progress = True
                    self.notify(
                        "Auto-locking due to inactivity.",
                        timeout=3,
                    )
                    asyncio.create_task(self.lock())
                    continue
                for name, t in list(
                    self._last_activity.items()
                ):
                    if now - t <= SESSION_IDLE_TIMEOUT:
                        continue
                    contact = self.db.get_contact(name)
                    if not contact or not contact.get(
                        "chat_started"
                    ):
                        continue
                    self.notify(
                        f"Session with {name} idle for "
                        f"{int((now - t) // 60)} min.",
                        timeout=4,
                    )
                    self._touch_activity(name)
            except Exception:
                pass

    async def _outbox_loop(self):
        while True:
            try:
                await asyncio.sleep(OUTBOX_RETRY_INTERVAL)
                if not self._outbox:
                    continue
                for name in list(self._outbox.keys()):
                    contact = self.db.get_contact(name)
                    if not contact or contact.get("blocked"):
                        self._outbox.pop(name, None)
                        continue
                    if self.db.is_blocked(name):
                        self._outbox.pop(name, None)
                        continue
                    if contact.get("pending") != 0:
                        self._outbox.pop(name, None)
                        continue
                    if not contact.get("session_established"):
                        continue
                    for msg in list(self._outbox.get(name, [])):
                        ok = await self.send_chat_message(
                            name, msg["text"],
                            reply_to=msg["reply_to"],
                            react_to=msg["react_to"],
                            from_outbox=True
                        )
                        if ok:
                            try:
                                self._outbox[name].remove(msg)
                            except Exception:
                                pass
                    if name in self._outbox and not self._outbox[name]:
                        del self._outbox[name]
            except Exception:
                pass

    async def _send_presence_now(self, contact_name):
        try:
            contact = self.db.get_contact(contact_name)
            if not contact:
                return

            if contact_name in self._pending_rotates:
                payload = self._pending_rotates[contact_name]
                ip, port = self._resolve_peer_address(contact)
                if ip and port:
                    resp = await send_request(
                        ip, port, payload,
                        timeout=PROBE_TIMEOUT
                    )
                    if resp:
                        self._pending_rotates.pop(
                            contact_name, None
                        )
                        try:
                            self.db.delete_pending_rotate(
                                contact_name
                            )
                        except Exception:
                            pass

            if not contact.get("session_established"):
                return
            ip, port = self._resolve_peer_address(contact)
            if not ip or not port:
                self._record_probe_failure(contact_name)
                return
            payload = self._signed(
                {
                    "type": "PRESENCE",
                    "from_name": self.user_name,
                    "status": "online",
                    "timestamp": _now_ms(),
                }
            )
            try:
                resp = await send_request(
                    ip, port, payload, timeout=PROBE_TIMEOUT
                )
            except Exception:
                resp = None
            if resp and resp.get("type") == "OK":
                self._record_probe_success(contact_name)
            else:
                self._record_probe_failure(contact_name)
        except Exception:
            self._record_probe_failure(contact_name)

    async def _send_offline_now(self, contact_name):
        try:
            contact = self.db.get_contact(contact_name)
            if not contact or not contact.get(
                "session_established"
            ):
                return
            ip, port = self._resolve_peer_address(contact)
            if not ip or not port:
                return
            payload = self._signed(
                {
                    "type": "PRESENCE",
                    "from_name": self.user_name,
                    "status": "offline",
                    "timestamp": _now_ms(),
                }
            )
            await send_request(
                ip, port, payload, timeout=PROBE_TIMEOUT
            )
        except Exception:
            pass

    async def broadcast_presence_now(self):
        if not self.db.get_presence_enabled():
            return
        try:
            contacts = self.db.get_contacts()
        except Exception:
            return
        tasks = []
        for contact in contacts:
            if not (
                contact.get("chat_started")
                and contact.get("session_established")
            ):
                continue
            tasks.append(
                self._send_presence_now(contact["name"])
            )
        if tasks:
            try:
                await asyncio.gather(
                    *tasks, return_exceptions=True
                )
            except Exception:
                pass

    async def broadcast_offline_now(self):
        try:
            contacts = self.db.get_contacts()
        except Exception:
            return
        tasks = []
        for contact in contacts:
            if not (
                contact.get("chat_started")
                and contact.get("session_established")
            ):
                continue
            tasks.append(
                self._send_offline_now(contact["name"])
            )
        if tasks:
            try:
                await asyncio.gather(
                    *tasks, return_exceptions=True
                )
            except Exception:
                pass

    async def _presence_loop(self):
        while True:
            try:
                await asyncio.sleep(PRESENCE_INTERVAL)
                if not self.db.get_presence_enabled():
                    continue
                await self.broadcast_presence_now()
            except Exception:
                pass

    async def send_typing(self, contact_name):
        self._global_last_activity = time.time()
        contact = self.db.get_contact(contact_name)
        if not contact:
            return
        if not contact.get("session_established"):
            return
        if contact.get("blocked") or self.db.is_blocked(
            contact_name
        ):
            return
        now = time.time()
        last = self._last_typing_sent.get(
            contact_name, 0
        )
        if now - last < TYPING_THROTTLE:
            return
        self._last_typing_sent[contact_name] = now
        try:
            ip, port = self._resolve_peer_address(contact)
            if not ip or not port:
                return
            payload = self._signed(
                {
                    "type": "TYPING",
                    "from_name": self.user_name,
                    "timestamp": _now_ms(),
                }
            )
            resp = await send_request(
                ip, port, payload, timeout=PROBE_TIMEOUT
            )
            if resp and resp.get("type") == "OK":
                self._touch_heard(contact_name)
        except Exception:
            pass

    def _current_code_tags(self):
        try:
            return [
                compute_secure_code_tag(
                    self.lookup_key,
                    compute_totp(self.totp_secret, 0),
                ),
                compute_secure_code_tag(
                    self.lookup_key,
                    compute_totp(self.totp_secret, -1),
                ),
            ]
        except Exception:
            return []

    async def rotate_keys(self):
        if self._pending_rotates:
            self.notify(
                "Cannot rotate: previous rotation not yet "
                "delivered to all contacts.",
                severity="error",
            )
            return
        old_ed = self.ed_private
        new_ed = generate_ed25519_private()
        new_ed_pub_hex = ed_public_to_bytes(
            new_ed.public_key()
        ).hex()
        new_x = x25519_generate()
        new_x_pub_hex = x25519_public_to_bytes(
            new_x.public_key()
        ).hex()

        fields = {
            "type": "ROTATE",
            "from_name": self.user_name,
            "new_ed_pub": new_ed_pub_hex,
            "new_x25519_pub": new_x_pub_hex,
            "timestamp": _now_ms(),
        }
        data = CONTROL_SIG_PREFIX + json.dumps(
            fields, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        sig = base64.b64encode(
            sign_bytes(old_ed, data)
        ).decode("ascii")
        payload = {**fields, "signature": sig}

        self.db.update_identity_keys(
            ed_private_to_bytes(new_ed).hex(),
            new_ed_pub_hex,
            x25519_private_to_bytes(new_x).hex(),
            new_x_pub_hex,
        )
        self.ed_private = new_ed
        self.ed_public = new_ed.public_key()
        self.x25519_private = new_x
        self.x25519_public = new_x.public_key()

        for c in self.db.get_contacts():
            if c.get("blocked"):
                continue
            if self.db.is_blocked(c["name"]):
                continue
            try:
                ip, port = self._resolve_peer_address(c)
                if ip and port:
                    resp = await send_request(
                        ip, port, payload, timeout=2.0
                    )
                    if not resp:
                        self._pending_rotates[
                            c["name"]
                        ] = payload
                        try:
                            self.db.save_pending_rotate(
                                c["name"], payload
                            )
                        except Exception:
                            pass
                else:
                    self._pending_rotates[c["name"]] = payload
                    try:
                        self.db.save_pending_rotate(
                            c["name"], payload
                        )
                    except Exception:
                        pass
            except Exception:
                self._pending_rotates[c["name"]] = payload
                try:
                    self.db.save_pending_rotate(
                        c["name"], payload
                    )
                except Exception:
                    pass

        self.notify("Keys rotated and broadcasted.")
        self._audit("KEYS_ROTATED")

    async def retry_pending_rotations(self):
        if not self._pending_rotates:
            self.notify("No pending rotations.")
            return
        delivered = 0
        failed = 0
        dropped = 0
        for name, payload in list(self._pending_rotates.items()):
            contact = self.db.get_contact(name)
            if not contact:
                self._pending_rotates.pop(name, None)
                try:
                    self.db.delete_pending_rotate(name)
                except Exception:
                    pass
                dropped += 1
                continue
            if contact.get("blocked") or self.db.is_blocked(name):
                failed += 1
                continue
            ip, port = self._resolve_peer_address(contact)
            if not ip or not port:
                failed += 1
                continue
            try:
                resp = await send_request(
                    ip, port, payload, timeout=PROBE_TIMEOUT
                )
                if resp:
                    self._pending_rotates.pop(name, None)
                    try:
                        self.db.delete_pending_rotate(name)
                    except Exception:
                        pass
                    delivered += 1
                else:
                    failed += 1
            except Exception:
                failed += 1
        msg = f"Rotations: {delivered} delivered, {failed} pending"
        if dropped:
            msg += f", {dropped} dropped"
        msg += "."
        self.notify(msg)

    async def block_contact(self, name):
        contact = self.db.get_contact(name)
        if not contact:
            self.notify(
                f"Contact {name} not found.",
                severity="error",
            )
            return
        if contact.get("blocked") or self.db.is_blocked(name):
            self.notify(
                f"{name} is already blocked.",
                severity="warning",
            )
            return
        if contact.get("chat_started"):
            try:
                await self.stop_chat(name)
            except Exception:
                pass
        self.db.set_contact_state(name, blocked=1)
        try:
            self.db.add_blocked(
                name, contact.get("ed_public_hex", "")
            )
        except Exception:
            pass
        self._audit("BLOCKED_LOCAL", {"contact": name})
        self._refresh_main()
        self._refresh_visible_messages()
        self.notify(f"Blocked {name}.")

    async def unblock_contact(self, name):
        contact = self.db.get_contact(name)
        in_table = self.db.is_blocked(name)
        if not in_table and (not contact or not contact.get(
            "blocked"
        )):
            self.notify(
                f"{name} is not blocked.",
                severity="warning",
            )
            return
        try:
            self.db.remove_blocked(name)
        except Exception:
            pass
    
        if hasattr(self, "_name_attempts"):
            self._name_attempts.pop(name, None)
        if contact:
            self.db.set_contact_state(name, blocked=0)
        self._audit("UNBLOCKED_LOCAL", {"contact": name})
        self._refresh_main()
        self._refresh_visible_messages()
        self.notify(f"Unblocked {name}.")

    def show_verify_screen(self, contact_name):
        contact = self.db.get_contact(contact_name)
        if not contact:
            return
        my_ed = ed_public_to_bytes(self.ed_public).hex()
        safety = compute_safety_number(
            my_ed, contact["ed_public_hex"]
        )
        self.push_screen(
            VerifyScreen(
                contact_name,
                safety,
                bool(contact.get("verified")),
            ),
            callback=lambda result: self._on_verify_result(
                contact_name, result
            ),
        )

    def _on_verify_result(self, contact_name, result):
        if result == "toggle":
            contact = self.db.get_contact(contact_name)
            if not contact:
                return
            new_val = 0 if contact.get("verified") else 1
            self.db.set_contact_state(
                contact_name, verified=new_val
            )
            self._audit(
                "VERIFIED" if new_val else "UNVERIFIED",
                {"contact": contact_name},
            )
            self._refresh_main()
            self._refresh_visible_messages()
            if new_val:
                self.notify(
                    f"{contact_name} marked verified."
                )
            else:
                self.notify(
                    f"{contact_name} marked unverified."
                )

    def _build_add_request_payload(self, code):
        challenge = os.urandom(32)
        proof = hmac.new(
            code.encode("utf-8"),
            b"REQ"
            + self.user_name.encode("utf-8")
            + challenge,
            hashlib.sha256,
        ).digest()
        fields = {
            "type": "ADD_REQUEST",
            "from_name": self.user_name,
            "from_ed_pub": ed_public_to_bytes(
                self.ed_public
            ).hex(),
            "from_x25519_pub": x25519_public_to_bytes(
                self.x25519_public
            ).hex(),
            "from_port": self.tcp_port,
            "challenge": base64.b64encode(
                challenge
            ).decode("ascii"),
            "proof": proof.hex(),
            "timestamp": _now_ms(),
        }
        return self._signed(fields)

    async def _process_add_response(
        self,
        resp,
        code,
        peer_ip,
        peer_port,
        expected_found_name=None,
        pinned=False,
    ):
        if not resp:
            self.notify(
                "Add failed: unreachable.",
                severity="error",
            )
            return False
        resp_type = resp.get("type")
        if resp_type == "ADD_REJECT":
            reason = resp.get("reason", "rejected")
            self.notify(
                f"Add failed: {reason}",
                severity="error",
            )
            self._audit(
                "ADD_REJECTED",
                {
                    "contact": (
                        expected_found_name or peer_ip
                    ),
                    "reason": reason,
                },
            )
            return False
        if resp_type not in ("ADD_ACCEPT", "ADD_PENDING"):
            self.notify(
                "Invalid peer response.",
                severity="error",
            )
            return False
        to_ed = resp.get("to_ed_pub", "")
        to_x = resp.get("to_x25519_pub", "")
        to_name = resp.get("to_name", "")
        challenge_b64 = resp.get("challenge", "")
        proof_hex = resp.get("proof", "")
        ts = resp.get("timestamp")
        if not self._valid_hex(to_ed, 32):
            self.notify(
                "Invalid peer key.", severity="error"
            )
            return False
        if not self._valid_hex(to_x, 32):
            self.notify(
                "Invalid peer key.", severity="error"
            )
            return False
        if not self._valid_name(to_name):
            self.notify(
                "Invalid peer name.", severity="error"
            )
            return False
        if to_name == self.user_name:
            self.notify(
                "Cannot add yourself.", severity="error"
            )
            return False
        if not self._valid_timestamp(ts):
            self.notify(
                "Stale response.", severity="error"
            )
            return False
        try:
            resp_challenge = base64.b64decode(
                challenge_b64
            )
        except Exception:
            self.notify(
                "Invalid challenge.", severity="error"
            )
            return False
        if len(resp_challenge) != 32:
            self.notify(
                "Invalid challenge.", severity="error"
            )
            return False
        expected = hmac.new(
            code.encode("utf-8"),
            b"ACC"
            + to_name.encode("utf-8")
            + resp_challenge,
            hashlib.sha256,
        ).digest()
        try:
            given = bytes.fromhex(proof_hex)
        except (TypeError, ValueError):
            self.notify(
                "Invalid proof.", severity="error"
            )
            return False
        if not hmac.compare_digest(expected, given):
            self.notify(
                "Proof mismatch - wrong peer or "
                "tampered response.",
                severity="error",
            )
            self._audit(
                "PROOF_MISMATCH",
                {"peer_name": to_name},
            )
            return False
        try:
            peer_ed_pk = ed_public_from_bytes(
                bytes.fromhex(to_ed)
            )
        except Exception:
            self.notify(
                "Invalid peer key.", severity="error"
            )
            return False
        if not self._check_signed(resp, peer_ed_pk):
            self.notify(
                "Invalid response signature.",
                severity="error",
            )
            return False
        if (
            expected_found_name is not None
            and expected_found_name != to_name
        ):
            self.notify(
                f"Name mismatch: expected "
                f"{expected_found_name}, got {to_name}.",
                severity="error",
            )
            return False
        contact_name = expected_found_name or to_name
        if self.db.is_blocked(contact_name):
            self.notify(
                f"{contact_name} is blocked. "
                "Unblock first.",
                severity="error",
            )
            return False
        existing = self.db.get_contact(contact_name)
        if (
            existing
            and existing["ed_public_hex"] != to_ed
        ):
            self.notify(
                f"Key mismatch for {contact_name}. "
                "Refusing to overwrite.",
                severity="error",
            )
            return False
        self.db.upsert_contact(
            name=contact_name,
            ip=peer_ip,
            port=peer_port,
            ed_public_hex=to_ed,
            x25519_public_hex=to_x,
        )
        if pinned:
            self.db.set_contact_state(
                contact_name, pinned=1
            )
        self._audit(
            "ADD_REQUEST_SENT", {"contact": contact_name}
        )
        if resp_type == "ADD_ACCEPT":
            self.db.set_contact_state(
                contact_name, pending=0
            )
            self.notify(f"Added {contact_name}.")
        else:
            self.db.set_contact_state(
                contact_name, pending=1
            )
            self.notify(
                f"Request sent to {contact_name}. "
                "Waiting for acceptance."
            )
        self._touch_heard(contact_name)
        self._refresh_main()
        self._refresh_visible_messages()
        return True

    async def add_contact_by_code(self, code):
        tag = compute_secure_code_tag(
            self.lookup_key, code
        )
        (
            found_name,
            info,
        ) = self.discovery.find_by_code_tag(
            tag, exclude_name=self.user_name
        )
        if not found_name:
            self.notify(
                "Searching for peer...", timeout=2
            )
            await asyncio.sleep(SEARCH_WAIT_SECONDS)
            (
                found_name,
                info,
            ) = self.discovery.find_by_code_tag(
                tag, exclude_name=self.user_name
            )
        if not found_name:
            self.notify(
                "No peer found with that code.",
                severity="error",
            )
            return False
        self.notify("Contacting peer...", timeout=2)
        payload = self._build_add_request_payload(code)
        resp = await send_request(
            info["ip"], info["tcp_port"], payload
        )
        return await self._process_add_response(
            resp,
            code,
            info["ip"],
            info["tcp_port"],
            expected_found_name=found_name,
            pinned=False,
        )

    async def add_contact_by_ip(self, ip, port, code):
        self.notify("Contacting peer...", timeout=2)
        payload = self._build_add_request_payload(code)
        resp = await send_request(ip, port, payload)
        return await self._process_add_response(
            resp,
            code,
            ip,
            port,
            expected_found_name=None,
            pinned=True,
        )

    async def start_chat(self, contact_name):
        contact = self.db.get_contact(contact_name)
        if not contact:
            return
        if contact.get("blocked") or self.db.is_blocked(
            contact_name
        ):
            self.notify(
                "Contact is blocked.", severity="error"
            )
            return
        if contact.get("pending") != 0:
            self.notify(
                "Contact is not accepted yet.",
                severity="error",
            )
            return
        if (
            self.db.get_verified_only()
            and not contact.get("verified")
        ):
            self.notify(
                "Contact is not verified. Verify or "
                "disable verified-only mode.",
                severity="error",
            )
            return
        if contact.get("chat_started") and contact.get(
            "session_established"
        ):
            self.notify("Chat is already active.")
            return
        ip, port = self._resolve_peer_address(contact)
        if not ip or not port:
            self._mark_offline(contact_name)
            self._refresh_main()
            self.notify(
                "Contact is offline.", severity="error"
            )
            return
        eph_sk = x25519_generate()
        eph_pub_raw = x25519_public_to_bytes(
            eph_sk.public_key()
        )
        payload = self._signed(
            {
                "type": "CHAT_START",
                "from_name": self.user_name,
                "eph_pub": base64.b64encode(
                    eph_pub_raw
                ).decode("ascii"),
                "timestamp": _now_ms(),
            }
        )
        resp = await send_request(ip, port, payload)
        if not resp:
            self._mark_offline(contact_name)
            self._refresh_main()
            self.notify(
                "Could not reach contact.",
                severity="error",
            )
            return
        if resp.get("type") == "CHAT_REJECT":
            reason = resp.get("reason", "unknown")
            if reason == "unverified":
                self.notify(
                    "Peer rejected: contact unverified.",
                    severity="error",
                )
            elif reason == "blocked":
                self.notify(
                    "Peer rejected: blocked.",
                    severity="error",
                )
            else:
                self.notify(
                    f"Rejected: {reason}",
                    severity="error",
                )
            return
        self.db.set_contact_state(
            contact_name,
            ip=ip,
            port=port,
            session_local_eph_sk_hex=(
                x25519_private_to_bytes(eph_sk).hex()
            ),
        )
        self._touch_activity(contact_name)
        self._touch_heard(contact_name)
        self._audit(
            "CHAT_START_SENT", {"contact": contact_name}
        )
        self.notify(
            f"Chat request sent to {contact_name}."
        )

    async def accept_contact(self, contact_name):
        contact = self.db.get_contact(contact_name)
        if not contact or contact.get("pending") != 2:
            return
        ip, port = self._resolve_peer_address(contact)
        if not ip or not port:
            self.notify(
                "Cannot reach contact.", severity="error"
            )
            return
        payload = self._signed(
            {
                "type": "ADD_ACCEPT",
                "from_name": self.user_name,
                "from_ed_pub": ed_public_to_bytes(
                    self.ed_public
                ).hex(),
                "from_x25519_pub": x25519_public_to_bytes(
                    self.x25519_public
                ).hex(),
                "timestamp": _now_ms(),
            }
        )
        resp = await send_request(ip, port, payload)
        if not resp:
            self.notify(
                "Could not reach contact.",
                severity="error",
            )
            return
        self.db.set_contact_state(
            contact_name, pending=0, ip=ip, port=port
        )
        self._touch_heard(contact_name)
        self._refresh_main()
        self.notify(f"Accepted {contact_name}.")
        self._audit(
            "ADD_ACCEPTED_LOCAL", {"contact": contact_name}
        )

    async def reject_contact(self, contact_name):
        contact = self.db.get_contact(contact_name)
        if not contact or contact.get("pending") != 2:
            return
        ip, port = self._resolve_peer_address(contact)
        if ip and port:
            payload = self._signed(
                {
                    "type": "ADD_REJECT",
                    "from_name": self.user_name,
                    "reason": "user_declined",
                    "timestamp": _now_ms(),
                }
            )
            await send_request(ip, port, payload)
        self.db.delete_contact(contact_name)
        self._contact_locks.pop(contact_name, None)
        self._peer_typing.pop(contact_name, None)
        self._last_activity.pop(contact_name, None)
        self._last_heard.pop(contact_name, None)
        self._peer_offline.pop(contact_name, None)
        self._presence_success.pop(contact_name, None)
        self._presence_fail.pop(contact_name, None)
        self._last_typing_sent.pop(contact_name, None)
        self._outbox.pop(contact_name, None)
        self._pending_rotates.pop(contact_name, None)
        try:
            self.db.delete_pending_rotate(contact_name)
        except Exception:
            pass
        self._refresh_main()
        self._refresh_visible_messages()
        self.notify(f"Rejected {contact_name}.")
        self._audit(
            "ADD_REJECTED_LOCAL",
            {"contact": contact_name},
        )

    async def accept_chat(self, contact_name):
        contact = self.db.get_contact(contact_name)
        if not contact:
            return
        if not contact.get("incoming_request"):
            self.notify(
                "No pending chat request.",
                severity="error",
            )
            return
        peer_eph_hex = contact.get(
            "session_peer_eph_pub_hex", ""
        )
        if not peer_eph_hex:
            self.notify(
                "No session ephemeral from peer.",
                severity="error",
            )
            return
        ip, port = self._resolve_peer_address(contact)
        if not ip or not port:
            self.notify(
                "Contact is offline.", severity="error"
            )
            return
        try:
            peer_eph_raw = bytes.fromhex(peer_eph_hex)
            peer_eph_pub = x25519_public_from_bytes(
                peer_eph_raw
            )
        except Exception:
            self.notify(
                "Bad peer ephemeral.", severity="error"
            )
            return
        eph_sk = x25519_generate()
        eph_pub_raw = x25519_public_to_bytes(
            eph_sk.public_key()
        )
        try:
            shared = eph_sk.exchange(peer_eph_pub)
        except Exception:
            self.notify(
                "Session setup failed.",
                severity="error",
            )
            return
        chains = derive_session_chains(
            shared, eph_pub_raw, peer_eph_raw
        )
        send_chain = chains[32:64]
        recv_chain = chains[0:32]
        payload = self._signed(
            {
                "type": "CHAT_ACCEPT",
                "from_name": self.user_name,
                "eph_pub": base64.b64encode(
                    eph_pub_raw
                ).decode("ascii"),
                "timestamp": _now_ms(),
            }
        )
        resp = await send_request(ip, port, payload)
        if not resp:
            self.notify(
                "Could not reach contact.",
                severity="error",
            )
            return
        self.db.set_contact_state(
            contact_name,
            chat_started=1,
            incoming_request=0,
            session_established=1,
            send_chain_key_hex=send_chain.hex(),
            recv_chain_key_hex=recv_chain.hex(),
            send_counter=0,
            recv_counter=0,
            session_local_eph_sk_hex="",
            session_peer_eph_pub_hex="",
            ip=ip,
            port=port,
        )
        self._touch_activity(contact_name)
        self._touch_heard(contact_name)
        self._refresh_main()
        self.notify(
            f"Chat accepted with {contact_name}."
        )
        self._audit(
            "CHAT_ACCEPTED_LOCAL",
            {"contact": contact_name},
        )
        asyncio.create_task(
            self._send_presence_now(contact_name)
        )

    async def reject_chat(self, contact_name):
        contact = self.db.get_contact(contact_name)
        if not contact or not contact.get(
            "incoming_request"
        ):
            return
        ip, port = self._resolve_peer_address(contact)
        if ip and port:
            payload = self._signed(
                {
                    "type": "CHAT_REJECT",
                    "from_name": self.user_name,
                    "timestamp": _now_ms(),
                }
            )
            await send_request(ip, port, payload)
        self.db.set_contact_state(
            contact_name,
            incoming_request=0,
            session_peer_eph_pub_hex="",
        )
        self._refresh_main()
        self.notify(
            f"Chat request from {contact_name} rejected."
        )

    async def accept_clear(self, contact_name):
        contact = self.db.get_contact(contact_name)
        if not contact or not contact.get("clear_pending"):
            self.notify(
                "No pending clear request.",
                severity="error",
            )
            return
        ip, port = self._resolve_peer_address(contact)
        sent = False
        if ip and port:
            payload = self._signed(
                {
                    "type": "CLEAR_ACCEPT",
                    "from_name": self.user_name,
                    "timestamp": _now_ms(),
                }
            )
            try:
                resp = await send_request(
                    ip, port, payload, timeout=STOP_TIMEOUT
                )
                sent = bool(resp)
                if sent:
                    self._touch_heard(contact_name)
            except Exception:
                sent = False
        self.db.clear_messages(contact_name)
        self.db.set_contact_state(
            contact_name, clear_pending=0
        )
        self._refresh_main()
        self._refresh_visible_messages()
        if sent:
            self.notify(
                f"Conversation with {contact_name} "
                "cleared on both sides."
            )
        else:
            self.notify(
                f"Cleared locally. Could not reach "
                f"{contact_name} to clear remotely.",
                severity="warning",
            )
        self._audit(
            "CLEAR_ACCEPTED_LOCAL",
            {"contact": contact_name, "notified": sent},
        )

    async def reject_clear(self, contact_name):
        contact = self.db.get_contact(contact_name)
        if not contact or not contact.get("clear_pending"):
            return
        ip, port = self._resolve_peer_address(contact)
        if ip and port:
            payload = self._signed(
                {
                    "type": "CLEAR_REJECT",
                    "from_name": self.user_name,
                    "timestamp": _now_ms(),
                }
            )
            try:
                await send_request(
                    ip, port, payload, timeout=STOP_TIMEOUT
                )
            except Exception:
                pass
        self.db.set_contact_state(
            contact_name, clear_pending=0
        )
        self._refresh_main()
        self.notify(
            f"Declined clear request from {contact_name}."
        )
        self._audit(
            "CLEAR_REJECTED_LOCAL",
            {"contact": contact_name},
        )

    async def send_chat_message(
        self,
        contact_name,
        text,
        reply_to=0,
        react_to=0,
        from_outbox=False
    ):
        self._global_last_activity = time.time()
        async with self._get_contact_lock(contact_name):
            contact = self.db.get_contact(contact_name)
            if not contact:
                return False
            if contact.get("blocked") or self.db.is_blocked(
                contact_name
            ):
                self.notify(
                    "Contact is blocked.", severity="error"
                )
                return False
            if contact.get("pending") != 0:
                self.notify(
                    "Contact is not accepted yet.",
                    severity="error",
                )
                return False
            if (
                self.db.get_verified_only()
                and not contact.get("verified")
            ):
                self.notify(
                    "Contact is not verified. Verify or "
                    "disable verified-only mode.",
                    severity="error",
                )
                return False
            if not contact.get("chat_started"):
                if not from_outbox:
                    self.notify(
                        "Chat not started. Press S to start it.",
                        severity="error",
                    )
                return False
            if not contact.get("session_established"):
                if not from_outbox:
                    self.notify(
                        "No active session. Start chat first.",
                        severity="error",
                    )
                return False
            if "\x00" in text:
                self.notify(
                    "Message contains invalid characters.",
                    severity="error",
                )
                return False
            if len(text) > MAX_MESSAGE_LEN:
                self.notify(
                    f"Message too long "
                    f"(max {MAX_MESSAGE_LEN}).",
                    severity="error",
                )
                return False
            reply_to = int(reply_to) if reply_to else 0
            react_to = int(react_to) if react_to else 0
            if reply_to < 0 or react_to < 0:
                self.notify(
                    "Invalid reply/react target.",
                    severity="error",
                )
                return False
            ip, port = self._resolve_peer_address(contact)
            if not ip or not port:
                self._mark_offline(contact_name)
                self._refresh_main()
                if not from_outbox:
                    self.notify(
                        "Contact is offline.", severity="error"
                    )
                return False
            send_chain_hex = contact.get(
                "send_chain_key_hex", ""
            )
            if not send_chain_hex:
                self.notify(
                    "No session chain. Restart chat.",
                    severity="error",
                )
                return False
            try:
                send_chain = bytes.fromhex(send_chain_hex)
            except ValueError:
                self.notify(
                    "Corrupted chain. Restart chat.",
                    severity="error",
                )
                return False
            counter = contact.get("send_counter", 0) + 1
            msg_key = chain_message_key(send_chain)
            try:
                padded = pad_message(text.encode("utf-8"))
                nonce = os.urandom(12)
                aad = (
                    f"{self.user_name}:{counter}".encode(
                        "utf-8"
                    )
                )
                ct = aes_gcm_encrypt(
                    msg_key, padded, nonce, aad
                )
            except Exception:
                self.notify(
                    "Encryption failed.", severity="error"
                )
                return False
            signed_data = (
                self.user_name.encode("utf-8")
                + counter.to_bytes(8, "big")
                + nonce
                + ct
                + reply_to.to_bytes(8, "big")
                + react_to.to_bytes(8, "big")
            )
            sig = sign_bytes(self.ed_private, signed_data)
            payload = {
                "type": "MESSAGE",
                "from_name": self.user_name,
                "counter": counter,
                "nonce": base64.b64encode(nonce).decode(
                    "ascii"
                ),
                "ciphertext": base64.b64encode(ct).decode(
                    "ascii"
                ),
                "signature": base64.b64encode(sig).decode(
                    "ascii"
                ),
            }
            if reply_to:
                payload["reply_to"] = reply_to
            if react_to:
                payload["react_to"] = react_to
            new_chain = chain_advance(send_chain)
            try:
                self.db.set_contact_state(
                    contact_name,
                    send_chain_key_hex=new_chain.hex(),
                    send_counter=counter,
                )
            except Exception:
                self.notify(
                    "State update failed.",
                    severity="error",
                )
                return False
            resp = await send_request(
                ip, port, payload, timeout=MESSAGE_TIMEOUT
            )
            if not resp:
                self._mark_offline(contact_name)
                self._refresh_main()
                if not from_outbox:
                    if contact_name not in self._outbox:
                        self._outbox[contact_name] = []
                    self._outbox[contact_name].append({
                        "text": text,
                        "reply_to": reply_to,
                        "react_to": react_to
                    })
                    self.notify(
                        "Message queued in outbox (peer offline).",
                        severity="warning",
                    )
                    return True
                return False

            rtype = resp.get("type")
            if rtype != "OK":
                reason = resp.get("reason", "unknown")
                self.notify(
                    f"Message rejected by peer: {reason}",
                    severity="error",
                )
                return False
            if not self.db.add_message(
                contact_name,
                "out",
                text,
                reply_to=reply_to,
                react_to=react_to,
            ):
                self.notify(
                    "Sent, but local history write failed.",
                    severity="warning",
                )
            self._touch_activity(contact_name)
            self._touch_heard(contact_name)
            self._refresh_visible_messages()
            return True

    def clear_chat_confirm(self, contact_name):
        self.push_screen(
            ConfirmScreen(
                f"Clear all messages with "
                f"{contact_name} locally?"
            ),
            callback=lambda ok: self._do_clear_chat(
                ok, contact_name
            ),
        )

    def _do_clear_chat(self, confirmed, contact_name):
        if confirmed:
            self.db.clear_messages(contact_name)
            self._refresh_main()
            self._refresh_visible_messages()
            self.notify(
                f"Cleared chat with {contact_name}."
            )
            self._audit(
                "CLEARED_LOCAL", {"contact": contact_name}
            )

    def clear_all_confirm(self, contact_name):
        self.push_screen(
            ConfirmScreen(
                f"Ask {contact_name} to clear the "
                "ENTIRE conversation on both sides?\n"
                "Both copies are cleared when they accept. "
                "Nothing is cleared until then."
            ),
            callback=lambda ok: self._do_clear_all(
                ok, contact_name
            ),
        )

    def _do_clear_all(self, confirmed, contact_name):
        if confirmed:
            asyncio.create_task(
                self.request_clear_all(contact_name)
            )

    async def request_clear_all(self, contact_name):
        contact = self.db.get_contact(contact_name)
        if not contact:
            return
        if contact.get("blocked") or self.db.is_blocked(
            contact_name
        ):
            self.notify(
                "Contact is blocked.", severity="error"
            )
            return
        if contact.get("pending") != 0:
            self.notify(
                "Contact is not accepted yet.",
                severity="error",
            )
            return
        ip, port = self._resolve_peer_address(contact)
        if not ip or not port:
            self.notify(
                "Contact is offline.", severity="error"
            )
            return
        payload = self._signed(
            {
                "type": "CLEAR_REQUEST",
                "from_name": self.user_name,
                "timestamp": _now_ms(),
            }
        )
        resp = await send_request(ip, port, payload)
        if not resp:
            self.notify(
                "Could not reach contact.",
                severity="error",
            )
            return
        resp_type = resp.get("type")
        if resp_type == "CLEAR_REJECT":
            self.notify(
                f"Rejected: "
                f"{resp.get('reason', 'unknown')}",
                severity="error",
            )
            return
        if resp_type != "CLEAR_PENDING":
            self.notify(
                "Unexpected response.",
                severity="error",
            )
            return
        self._touch_heard(contact_name)
        self._audit(
            "CLEAR_REQUEST_SENT",
            {"contact": contact_name},
        )
        self.notify(
            f"Clear request sent to {contact_name}. "
            "Waiting for them to accept."
        )

    def stop_chat_confirm(self, contact_name):
        self.push_screen(
            ConfirmScreen(
                f"Stop the chat with {contact_name}?"
            ),
            callback=lambda ok: self._do_stop_chat(
                ok, contact_name
            ),
        )

    def _do_stop_chat(self, confirmed, contact_name):
        if confirmed:
            asyncio.create_task(
                self._safe_stop_chat(contact_name)
            )

    async def _safe_stop_chat(self, contact_name):
        try:
            await self.stop_chat(contact_name)
        except Exception as e:
            self.notify(
                f"Stop failed: {type(e).__name__}: {e}",
                severity="error",
            )

    async def stop_chat(self, contact_name):
        contact = self.db.get_contact(contact_name)
        if not contact:
            return
        if not contact.get("chat_started"):
            self.notify(
                "No active chat.", severity="error"
            )
            return
        ip, port = self._resolve_peer_address(contact)
        if ip and port:
            try:
                payload = self._signed(
                    {
                        "type": "CHAT_STOP",
                        "from_name": self.user_name,
                        "timestamp": _now_ms(),
                    }
                )
                resp = await send_request(
                    ip, port, payload, timeout=STOP_TIMEOUT
                )
                if resp:
                    self._touch_heard(contact_name)
            except Exception:
                pass
        self.db.set_contact_state(
            contact_name,
            chat_started=0,
            incoming_request=0,
            session_established=0,
            send_chain_key_hex="",
            recv_chain_key_hex="",
            send_counter=0,
            recv_counter=0,
            session_local_eph_sk_hex="",
            session_peer_eph_pub_hex="",
        )
        self._last_activity.pop(contact_name, None)
        self._last_heard.pop(contact_name, None)
        self._peer_offline.pop(contact_name, None)
        self._peer_typing.pop(contact_name, None)
        self._presence_success.pop(contact_name, None)
        self._presence_fail.pop(contact_name, None)
        self._last_typing_sent.pop(contact_name, None)
        self._outbox.pop(contact_name, None)
        self._refresh_main()
        self._refresh_visible_messages()
        self.notify(
            f"Chat with {contact_name} stopped."
        )
        self._audit(
            "CHAT_STOP_SENT", {"contact": contact_name}
        )

    def delete_message_confirm(self, message_id):
        self.push_screen(
            ConfirmScreen(
                f"Delete message #{message_id}?"
            ),
            callback=lambda ok: self._do_delete_message(
                ok, message_id
            ),
        )

    def _do_delete_message(self, confirmed, message_id):
        if confirmed:
            self.db.delete_message(message_id)
            self._refresh_visible_messages()
            self.notify(
                f"Deleted message #{message_id}."
            )

    def delete_contact_confirm(self, contact_name):
        self.push_screen(
            ConfirmScreen(
                f"Delete contact {contact_name} and "
                "all messages with them?"
            ),
            callback=lambda ok: self._do_delete_contact(
                ok, contact_name
            ),
        )

    def _do_delete_contact(self, confirmed, contact_name):
        if confirmed:
            self.db.delete_contact(contact_name)
            self._contact_locks.pop(contact_name, None)
            self._peer_typing.pop(contact_name, None)
            self._last_activity.pop(contact_name, None)
            self._last_heard.pop(contact_name, None)
            self._peer_offline.pop(contact_name, None)
            self._presence_success.pop(contact_name, None)
            self._presence_fail.pop(contact_name, None)
            self._last_typing_sent.pop(contact_name, None)
            self._outbox.pop(contact_name, None)
            self._pending_rotates.pop(contact_name, None)
            try:
                self.db.delete_pending_rotate(contact_name)
            except Exception:
                pass
            screen = self._get_main_screen()
            if (
                screen is not None
                and screen.current_contact == contact_name
            ):
                screen.load_messages_for(None)
            self._refresh_main()
            self._refresh_visible_messages()
            self.notify(
                f"Deleted contact {contact_name}."
            )
            self._audit(
                "CONTACT_DELETED", {"contact": contact_name}
            )

    async def perform_reset(self):
        try:
            await self.broadcast_offline_now()
        except Exception:
            pass
        try:
            await self._stop_networking()
        except Exception:
            pass
        try:
            self._audit("RESET")
        except Exception:
            pass
        try:
            self.db.reset_all()
        except Exception:
            pass
        self._zero_keys()
        self.user_name = None
        self.tcp_port = None
        self._add_attempts = {}
        self._name_attempts = {}
        self._msg_attempts = {}
        self._contact_locks = {}
        self._peer_typing = {}
        self._last_activity = {}
        self._last_heard = {}
        self._peer_offline = {}
        self._presence_success = {}
        self._presence_fail = {}
        self._last_typing_sent = {}
        self._outbox = {}
        self._pending_rotates = {}
        self._auto_lock_in_progress = False
        while len(self.screen_stack) > 1:
            self.pop_screen()
        screen = self.screen
        if isinstance(screen, StartupScreen):
            screen.refresh_state()
        else:
            self.push_screen(StartupScreen(self.db))
        self.notify("All data wiped.")

    def _get_main_screen(self):
        for screen in self.screen_stack:
            if isinstance(screen, MainScreen):
                return screen
        return None

    def _refresh_main(self):
        screen = self._get_main_screen()
        if screen is not None:
            screen.refresh_contacts()

    def _refresh_visible_messages(self):
        screen = self._get_main_screen()
        if (
            screen is not None
            and screen.current_contact
        ):
            screen.load_messages_for(
                screen.current_contact
            )