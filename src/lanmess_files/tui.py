import asyncio
import base64
import hashlib
import hmac
import json
import os
import re
import signal
import socket
import time

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import (
    Container,
    Horizontal,
    Vertical,
    VerticalScroll,
)
from textual.screen import ModalScreen, Screen
from textual.widgets import (
    Button,
    Footer,
    Header,
    Input,
    Label,
    ListItem,
    ListView,
    RichLog,
    Static,
)

from .config import (
    ADD_RATE_LIMIT_MAX,
    ADD_RATE_LIMIT_SECONDS,
    APP_NAME,
    APP_VERSION,
    CONTROL_SIG_PREFIX,
    DB_PATH,
    HISTORY_MAX,
    MAX_CHAIN_GAP,
    MAX_GROUP_CODE_LEN,
    MAX_MESSAGE_LEN,
    MESSAGE_TIMEOUT,
    MIN_GROUP_CODE_LEN,
    MSG_RATE_LIMIT_MAX,
    MSG_RATE_LIMIT_SECONDS,
    NOTIFY_BODY_MAX,
    ONLINE_WINDOW,
    PIN_MAX_LEN,
    PIN_MIN_LEN,
    PRESENCE_INTERVAL,
    REPLAY_WINDOW_SECONDS,
    SEARCH_WAIT_SECONDS,
    SESSION_IDLE_TIMEOUT,
    STOP_TIMEOUT,
    TCP_PORT_RANGE,
    TYPING_DISPLAY_TTL,
    TYPING_THROTTLE,
    UNREAD_MAX,
    ensure_dirs,
)
from .crypto import (
    aes_gcm_decrypt,
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
    totp_remaining,
    unpad_message,
    verify_bytes,
    verify_totp,
    x25519_generate,
    x25519_private_from_bytes,
    x25519_private_to_bytes,
    x25519_public_from_bytes,
    x25519_public_to_bytes,
)
from .database import Database
from .discovery import Discovery
from .network import Server, send_request
from .notifications import notify


def _now_ms():
    return int(time.time() * 1000)


def _check_pin_strength(pin):
    if not pin:
        return "PIN required."
    if len(pin) < PIN_MIN_LEN:
        return (
            f"PIN must be at least {PIN_MIN_LEN} characters."
        )
    if len(pin) > PIN_MAX_LEN:
        return f"PIN too long (max {PIN_MAX_LEN})."
    classes = 0
    if re.search(r"[a-z]", pin):
        classes += 1
    if re.search(r"[A-Z]", pin):
        classes += 1
    if re.search(r"[0-9]", pin):
        classes += 1
    if re.search(r"[^a-zA-Z0-9]", pin):
        classes += 1
    if classes < 3:
        return (
            "PIN must contain at least 3 of: "
            "lowercase, uppercase, digit, symbol."
        )
    if len(set(pin)) < 6:
        return "PIN uses too few distinct characters."
    return None


def _valid_port(s):
    if not isinstance(s, str):
        return False
    if not s.isdigit():
        return False
    n = int(s)
    return 1 <= n <= 65535


def _valid_ipv4(s):
    if not isinstance(s, str):
        return False
    parts = s.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit():
            return False
        n = int(p)
        if not (0 <= n <= 255):
            return False
    return True


def get_local_ips():
    ips = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ips.append(s.getsockname()[0])
        finally:
            s.close()
    except Exception:
        pass
    try:
        import subprocess

        result = subprocess.run(
            ["ip", "-4", "-o", "addr", "show"],
            capture_output=True,
            text=True,
            timeout=2,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                parts = line.split()
                if "inet" in parts:
                    idx = parts.index("inet")
                    if idx + 1 < len(parts):
                        addr = parts[idx + 1].split("/")[0]
                        if (
                            not addr.startswith("127.")
                            and addr not in ips
                        ):
                            ips.append(addr)
    except Exception:
        pass
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(
            hostname, None, socket.AF_INET
        ):
            addr = info[4][0]
            if addr not in ips and not addr.startswith("127."):
                ips.append(addr)
    except Exception:
        pass
    return ips or ["127.0.0.1"]


class ConfirmScreen(ModalScreen):
    CSS = """
    ConfirmScreen { align: center middle; }
    #confirm-box {
        width: 70;
        height: auto;
        border: thick $warning;
        padding: 2 3;
        background: $surface;
    }
    #confirm-message {
        padding: 0 0 1 0;
        text-align: center;
    }
    #confirm-buttons { height: auto; }
    #confirm-buttons Button {
        width: 100%;
        margin: 0 0 1 0;
    }
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=False),
    ]

    def __init__(self, message):
        super().__init__()
        self.message = message

    def compose(self) -> ComposeResult:
        with Container(id="confirm-box"):
            yield Static(self.message, id="confirm-message")
            with Vertical(id="confirm-buttons"):
                yield Button(
                    "Confirm", id="confirm", variant="error"
                )
                yield Button(
                    "Cancel", id="cancel", variant="primary"
                )

    def on_button_pressed(self, event):
        if event.button.id == "confirm":
            self.dismiss(True)
        else:
            self.dismiss(False)

    def action_cancel(self):
        self.dismiss(False)


class AddCodeScreen(ModalScreen):
    CSS = """
    AddCodeScreen { align: center middle; }
    #code-box {
        width: 44;
        height: auto;
        border: thick $accent;
        padding: 2 3;
        background: $surface;
    }
    #code-title {
        text-align: center;
        text-style: bold;
        color: $accent;
        padding: 0 0 1 0;
    }
    #code-value {
        text-align: center;
        text-style: bold;
        color: $success;
        padding: 1 0;
    }
    #code-timer {
        text-align: center;
        color: $text-muted;
        padding: 0 0 1 0;
    }
    #code-note {
        text-align: center;
        color: $text-muted;
        padding: 0 0 1 0;
    }
    #code-close { width: 100%; }
    """

    BINDINGS = [
        Binding("escape", "close", "Close", show=False),
        Binding("ctrl+z", "close", "Close", show=False),
    ]

    def compose(self) -> ComposeResult:
        with Container(id="code-box"):
            yield Static("Add Code", id="code-title")
            yield Static("", id="code-value")
            yield Static("", id="code-timer")
            yield Static(
                "Share only with people you want to add "
                "you. Valid for 60s, rotates automatically.",
                id="code-note",
            )
            yield Button(
                "Close", id="code-close", variant="primary"
            )

    def on_mount(self):
        self._update()
        self.set_interval(1.0, self._update)

    def _update(self):
        try:
            code = compute_totp(self.app.totp_secret)
            remaining = totp_remaining()
            self.query_one(
                "#code-value", Static
            ).update(f"[bold]{code}[/bold]")
            self.query_one(
                "#code-timer", Static
            ).update(f"Valid for {remaining}s")
        except Exception:
            pass

    def on_button_pressed(self, event):
        if event.button.id == "code-close":
            self.dismiss()

    def action_close(self):
        self.dismiss()


class AddByIpScreen(ModalScreen):
    CSS = """
    AddByIpScreen { align: center middle; }
    #addip-box {
        width: 62;
        height: auto;
        border: thick $accent;
        padding: 2 3;
        background: $surface;
    }
    #addip-title {
        text-align: center;
        text-style: bold;
        color: $accent;
        padding: 0 0 1 0;
    }
    #addip-note {
        color: $text-muted;
        padding: 0 0 1 0;
        text-align: center;
    }
    #addip-pin-note {
        color: $success;
        padding: 0 0 1 0;
        text-align: center;
    }
    AddByIpScreen Input { margin: 0 0 1 0; }
    #addip-error {
        color: $error;
        height: auto;
        padding: 0 0 1 0;
        text-align: center;
    }
    AddByIpScreen Button {
        width: 100%;
        margin: 0 0 1 0;
    }
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=False),
    ]

    def compose(self) -> ComposeResult:
        with Container(id="addip-box"):
            yield Static("Add by IP", id="addip-title")
            yield Static(
                "Enter the peer's address and the 8-digit "
                "code they show under Show add code.",
                id="addip-note",
            )
            yield Static(
                "Address will be pinned: won't be overwritten "
                "when the peer's LAN IP changes.",
                id="addip-pin-note",
            )
            yield Input(
                placeholder="IP (e.g. 192.168.1.42)",
                id="addip-ip",
            )
            yield Input(
                placeholder="Port (e.g. 50510)",
                id="addip-port",
            )
            yield Input(
                placeholder="8-digit add code",
                id="addip-code",
                max_length=8,
            )
            yield Static("", id="addip-error")
            yield Button(
                "Add", id="addip-add", variant="primary"
            )
            yield Button(
                "Cancel", id="addip-cancel", variant="default"
            )

    def _set_error(self, msg):
        try:
            self.query_one(
                "#addip-error", Static
            ).update(msg)
        except Exception:
            pass

    def on_button_pressed(self, event):
        if event.button.id == "addip-cancel":
            self.dismiss(None)
            return
        if event.button.id != "addip-add":
            return
        ip = self.query_one("#addip-ip", Input).value.strip()
        port_str = self.query_one(
            "#addip-port", Input
        ).value.strip()
        code = self.query_one(
            "#addip-code", Input
        ).value.strip()
        if not _valid_ipv4(ip):
            self._set_error("Invalid IPv4 address.")
            return
        if not _valid_port(port_str):
            self._set_error("Port must be 1-65535.")
            return
        if len(code) != 8 or not code.isdigit():
            self._set_error("Code must be exactly 8 digits.")
            return
        self.dismiss((ip, int(port_str), code))

    def action_cancel(self):
        self.dismiss(None)


class MyAddressScreen(ModalScreen):
    CSS = """
    MyAddressScreen { align: center middle; }
    #addr-box {
        width: 60;
        height: auto;
        border: thick $accent;
        padding: 2 3;
        background: $surface;
    }
    #addr-title {
        text-align: center;
        text-style: bold;
        color: $accent;
        padding: 0 0 1 0;
    }
    .addr-line {
        text-align: center;
        text-style: bold;
        color: $success;
        padding: 0 0 1 0;
    }
    #addr-note {
        color: $text-muted;
        padding: 1 0;
        text-align: center;
    }
    #addr-close { width: 100%; }
    """

    BINDINGS = [
        Binding("escape", "close", "Close", show=False),
    ]

    def __init__(self, ips, port):
        super().__init__()
        self.ips = ips
        self.port = port

    def compose(self) -> ComposeResult:
        with Container(id="addr-box"):
            yield Static("My Address", id="addr-title")
            for i, ip in enumerate(self.ips):
                yield Static(
                    f"{ip}:{self.port}",
                    id=f"addr-line-{i}",
                    classes="addr-line",
                )
            yield Static(
                "Share one of these addresses together "
                "with the code from 'Show add code' so "
                "the other person can add you by IP.",
                id="addr-note",
            )
            yield Button(
                "Close", id="addr-close", variant="primary"
            )

    def on_button_pressed(self, event):
        if event.button.id == "addr-close":
            self.dismiss()

    def action_close(self):
        self.dismiss()


class MenuScreen(ModalScreen):
    CSS = """
    MenuScreen { align: center middle; }
    #menu-box {
        width: 60;
        height: auto;
        max-height: 90%;
        border: thick $accent;
        background: $surface;
        padding: 1 2;
    }
    #menu-title {
        text-align: center;
        text-style: bold;
        color: $accent;
        padding: 0 0 1 0;
    }
    #menu-body {
        height: auto;
        max-height: 26;
    }
    .menu-section {
        text-style: bold;
        color: $accent;
        padding: 1 0 0 1;
        height: 1;
    }
    #menu-body Button {
        width: 100%;
        margin: 0 0 0 0;
    }
    """

    BINDINGS = [
        Binding("escape", "dismiss_menu", "Close", show=False),
        Binding("m", "dismiss_menu", "Close", show=False),
    ]

    def __init__(
        self,
        verified_only=False,
        notifications_enabled=True,
        presence_enabled=True,
    ):
        super().__init__()
        self.verified_only = verified_only
        self.notifications_enabled = notifications_enabled
        self.presence_enabled = presence_enabled

    def compose(self) -> ComposeResult:
        with Container(id="menu-box"):
            yield Static("Menu", id="menu-title")
            with VerticalScroll(id="menu-body"):
                yield Static("Chat", classes="menu-section")
                yield Button(
                    "Start chat (S)",
                    id="m-start",
                    variant="primary",
                )
                yield Button(
                    "Accept (Y)",
                    id="m-accept",
                    variant="success",
                )
                yield Button(
                    "Reject (X)",
                    id="m-reject",
                    variant="warning",
                )
                yield Button(
                    "Stop chat (T)",
                    id="m-stop",
                    variant="warning",
                )
                yield Button(
                    "Verify contact (V)", id="m-verify"
                )
                yield Button(
                    "Add by IP (I)", id="m-addip"
                )
                yield Static("History", classes="menu-section")
                yield Button(
                    "Clear local history (C)", id="m-clear"
                )
                yield Button(
                    "Request clear-all (both sides)",
                    id="m-clearall",
                )
                yield Button(
                    "Delete contact (D)",
                    id="m-delete",
                    variant="error",
                )
                yield Static("Privacy", classes="menu-section")
                yield Button(
                    f"Verified-only: "
                    f"{'ON' if self.verified_only else 'OFF'}",
                    id="m-vonl",
                )
                yield Button(
                    f"Notifications: "
                    f"{'ON' if self.notifications_enabled else 'OFF'}",
                    id="m-notif",
                )
                yield Button(
                    f"Presence: "
                    f"{'ON' if self.presence_enabled else 'OFF'}",
                    id="m-presence",
                )
                yield Static("Session", classes="menu-section")
                yield Button(
                    "Show my address", id="m-address"
                )
                yield Button(
                    "Show add code (Ctrl+Z)", id="m-code"
                )
                yield Button(
                    "Lock (Ctrl+L)", id="m-lock"
                )
                yield Static("System", classes="menu-section")
                yield Button("Help (?)", id="m-help")
                yield Button(
                    "Reset everything (Ctrl+R)",
                    id="m-reset",
                    variant="error",
                )
                yield Static("", classes="menu-section")
                yield Button(
                    "Close", id="m-close", variant="primary"
                )

    def on_button_pressed(self, event):
        self.dismiss(event.button.id[2:])

    def action_dismiss_menu(self):
        self.dismiss(None)


class VerifyScreen(ModalScreen):
    CSS = """
    VerifyScreen { align: center middle; }
    #verify-box {
        width: 80;
        height: auto;
        border: thick $accent;
        padding: 2 3;
        background: $surface;
    }
    #verify-title {
        text-align: center;
        text-style: bold;
        color: $accent;
        padding: 0 0 1 0;
    }
    #verify-number {
        text-align: center;
        text-style: bold;
        color: $success;
        padding: 1 0;
    }
    #verify-note {
        text-align: center;
        color: $text-muted;
        padding: 0 0 1 0;
    }
    #verify-buttons { height: auto; }
    #verify-buttons Button {
        width: 100%;
        margin: 0 0 1 0;
    }
    """

    BINDINGS = [
        Binding("escape", "cancel", "Close", show=False),
    ]

    def __init__(self, contact_name, safety_number, verified):
        super().__init__()
        self.contact_name = contact_name
        self.safety_number = safety_number
        self.verified = verified

    def compose(self) -> ComposeResult:
        with Container(id="verify-box"):
            yield Static(
                f"Verify {self.contact_name}",
                id="verify-title",
            )
            yield Static(
                self.safety_number, id="verify-number"
            )
            yield Static(
                "Read this number aloud, compare in person, "
                "or send it over a channel you already trust. "
                "If it matches, mark verified.",
                id="verify-note",
            )
            with Vertical(id="verify-buttons"):
                if self.verified:
                    yield Button(
                        "Mark unverified",
                        id="toggle",
                        variant="warning",
                    )
                else:
                    yield Button(
                        "Mark verified",
                        id="toggle",
                        variant="success",
                    )
                yield Button(
                    "Close", id="close", variant="primary"
                )

    def on_button_pressed(self, event):
        if event.button.id == "toggle":
            self.dismiss("toggle")
        else:
            self.dismiss(None)

    def action_cancel(self):
        self.dismiss(None)


class HelpScreen(ModalScreen):
    CSS = """
    HelpScreen { align: center middle; }
    #help-box {
        width: 82;
        height: auto;
        border: thick $accent;
        padding: 2 3;
        background: $surface;
    }
    #help-title {
        text-align: center;
        text-style: bold;
        color: $accent;
        padding: 0 0 1 0;
    }
    #help-content { height: auto; }
    #help-close {
        width: 100%;
        margin: 1 0 0 0;
    }
    """

    BINDINGS = [
        Binding("escape", "close", "Close", show=False),
        Binding("q", "close", "Close", show=False),
        Binding("question_mark", "close", "Close", show=False),
    ]

    def compose(self) -> ComposeResult:
        with Container(id="help-box"):
            yield Static("Help", id="help-title")
            yield Static(
                "Commands:\n"
                "  /help          Show this help\n"
                "  /menu          Open the action menu\n"
                "  /addip         Add by IP and port\n"
                "  /address       Show your IPs and port\n"
                "  /code          Show your add code\n"
                "  /verify        Show safety number\n"
                "  /find <text>   Search messages\n"
                "  /reply <id> <t> Reply to message\n"
                "  /react <id> <e> React to message\n"
                "  /clear         Clear local history\n"
                "  /clearall      Ask to clear both sides\n"
                "  /stop          Stop the chat\n"
                "  /del <id>      Delete message #id\n"
                "  /del           Delete most recent\n"
                "\n"
                "Keys:\n"
                "  M          Open menu\n"
                "  I          Add by IP\n"
                "  Ctrl+Z     Show add code\n"
                "  Ctrl+L     Lock\n"
                "  Ctrl+Q     Quit\n"
                "  ?          This help\n"
                "  A/S/Y/X    Add/Start/Accept/Reject\n"
                "  C/D/T/V    Clear/Delete/Stop/Verify\n"
                "  Up/Down    Message history\n"
                "\n"
                "Security (v1.1.9):\n"
                "  Per-session X25519 + hash ratchet.\n"
                "  Ed25519 signatures on every frame.\n"
                "  256-byte padding on messages.\n"
                "  Safety numbers for identity proof.\n"
                "  Random per-device master wrapped\n"
                "  with Argon2id(PIN).\n"
                "  HMAC-chained audit log.\n"
                "  PIN lockout after 5 failures.\n"
                "  Optional verified-only and idle\n"
                "  session timeout.",
                id="help-content",
            )
            yield Button(
                "Close", id="help-close", variant="primary"
            )

    def on_button_pressed(self, event):
        if event.button.id == "help-close":
            self.dismiss()

    def action_close(self):
        self.dismiss()


class StartupScreen(Screen):
    CSS = """
    StartupScreen { align: center middle; }
    #startup-box {
        width: 76;
        height: auto;
        border: thick $primary;
        padding: 2 3;
        background: $surface;
    }
    #startup-title {
        text-align: center;
        text-style: bold;
        padding: 0 0 1 0;
        color: $accent;
    }
    #startup-welcome {
        text-align: center;
        padding: 0 0 1 0;
    }
    #startup-note {
        text-align: center;
        color: $text-muted;
        padding: 0 0 1 0;
    }
    #startup-status {
        text-align: center;
        color: $warning;
        text-style: italic;
        height: 1;
        padding: 0 0 1 0;
    }
    StartupScreen Input { margin: 0 0 1 0; }
    StartupScreen Button {
        width: 100%;
        margin: 0 0 1 0;
    }
    #startup-error {
        color: $error;
        height: auto;
        padding: 1 0 0 0;
        text-align: center;
    }
    """

    BINDINGS = [
        Binding("ctrl+q", "quit_app", "Quit", show=True),
    ]

    def __init__(self, db):
        super().__init__()
        self.db = db
        self.state = db.get_state()

    def compose(self) -> ComposeResult:
        with Container(id="startup-box"):
            yield Static(
                f"{APP_NAME} v{APP_VERSION}",
                id="startup-title",
            )
            if self.state == "empty":
                yield Static(
                    "First-time setup. The group code is "
                    "used once to derive shared keys, then "
                    "your PIN unlocks the local database.",
                    id="startup-note",
                )
                yield Input(
                    placeholder="Your display name",
                    id="name",
                )
                yield Input(
                    placeholder=(
                        f"Group code (min {MIN_GROUP_CODE_LEN})"
                    ),
                    password=True,
                    id="group_code",
                )
                yield Input(
                    placeholder=(
                        f"PIN (min {PIN_MIN_LEN}, 3 of "
                        "lower/upper/digit/symbol)"
                    ),
                    password=True,
                    id="pin",
                )
                yield Input(
                    placeholder="Confirm PIN",
                    password=True,
                    id="pin_confirm",
                )
                yield Button(
                    "Create",
                    id="btn-action",
                    variant="primary",
                )
            elif self.state == "needs_vault":
                yield Static(
                    "Migrating to v1.1.9. Enter your old "
                    "group code once, then choose a PIN.",
                    id="startup-note",
                )
                yield Input(
                    placeholder="Existing group code",
                    password=True,
                    id="group_code",
                )
                yield Input(
                    placeholder=f"New PIN (min {PIN_MIN_LEN})",
                    password=True,
                    id="pin",
                )
                yield Input(
                    placeholder="Confirm PIN",
                    password=True,
                    id="pin_confirm",
                )
                yield Button(
                    "Migrate",
                    id="btn-action",
                    variant="primary",
                )
                yield Button(
                    "Reset all data",
                    id="btn-reset",
                    variant="error",
                )
            else:
                yield Static(
                    "Enter your PIN to unlock.",
                    id="startup-welcome",
                )
                yield Static(
                    "The PIN unwraps your random device "
                    "master via Argon2id. There is no "
                    "recovery if you forget it.",
                    id="startup-note",
                )
                yield Input(
                    placeholder="PIN",
                    password=True,
                    id="pin",
                )
                yield Button(
                    "Unlock",
                    id="btn-action",
                    variant="primary",
                )
                yield Button(
                    "Reset all data",
                    id="btn-reset",
                    variant="error",
                )
            yield Static("", id="startup-status")
            yield Static("", id="startup-error")

    def refresh_state(self):
        new_state = self.db.get_state()
        if new_state != self.state:
            self.state = new_state
            self.refresh(recompose=True)

    def _set_status(self, msg):
        try:
            self.query_one(
                "#startup-status", Static
            ).update(msg)
        except Exception:
            pass

    def _set_error(self, msg):
        try:
            self.query_one(
                "#startup-error", Static
            ).update(msg)
        except Exception:
            pass

    async def on_input_submitted(self, event):
        if event.input.id in (
            "pin",
            "pin_confirm",
            "group_code",
        ):
            await self._submit()

    async def on_button_pressed(self, event):
        if event.button.id == "btn-reset":
            self.app.push_screen(
                ConfirmScreen(
                    "RESET EVERYTHING?\n"
                    "This wipes your identity, contacts, "
                    "PIN, audit log and all messages. "
                    "Irreversible."
                ),
                callback=self._on_reset_confirmed,
            )
            return
        if event.button.id == "btn-action":
            await self._submit()

    def _on_reset_confirmed(self, confirmed):
        if confirmed:
            asyncio.create_task(self.app.perform_reset())

    async def _submit(self):
        for btn in self.query("Button"):
            btn.disabled = True
        try:
            self._set_error("")
            if self.state == "empty":
                await self._do_create()
            elif self.state == "needs_vault":
                await self._do_migrate()
            else:
                await self._do_unlock()
        except Exception as exc:
            self._set_error(str(exc))
        finally:
            try:
                for btn in self.query("Button"):
                    btn.disabled = False
            except Exception:
                pass

    async def _do_create(self):
        name = self.query_one("#name", Input).value.strip()
        code = self.query_one("#group_code", Input).value
        pin = self.query_one("#pin", Input).value
        pin2 = self.query_one("#pin_confirm", Input).value
        if not name or not code:
            self._set_error(
                "Name and group code required."
            )
            return
        if not self.app._valid_name(name):
            self._set_error(
                "Name must be 1-40 chars, no control "
                "characters."
            )
            return
        if len(code) < MIN_GROUP_CODE_LEN:
            self._set_error(
                f"Group code must be at least "
                f"{MIN_GROUP_CODE_LEN} characters."
            )
            return
        if len(code) > MAX_GROUP_CODE_LEN:
            self._set_error(
                f"Group code too long "
                f"(max {MAX_GROUP_CODE_LEN})."
            )
            return
        pin_err = _check_pin_strength(pin)
        if pin_err:
            self._set_error(pin_err)
            return
        if pin != pin2:
            self._set_error("PINs do not match.")
            return
        self._set_status("Creating (Argon2id)...")
        try:
            await self.app.create_identity(name, code, pin)
        finally:
            self._set_status("")

    async def _do_migrate(self):
        code = self.query_one("#group_code", Input).value
        pin = self.query_one("#pin", Input).value
        pin2 = self.query_one("#pin_confirm", Input).value
        if not code:
            self._set_error("Group code required.")
            return
        pin_err = _check_pin_strength(pin)
        if pin_err:
            self._set_error(pin_err)
            return
        if pin != pin2:
            self._set_error("PINs do not match.")
            return
        self._set_status("Migrating (Argon2id)...")
        try:
            ok = await self.app.migrate_needs_vault(code, pin)
        finally:
            self._set_status("")
        if not ok:
            self._set_error("Wrong group code.")

    async def _do_unlock(self):
        pin = self.query_one("#pin", Input).value
        if not pin:
            self._set_error("PIN required.")
            return
        self._set_status("Unlocking (Argon2id)...")
        try:
            ok = await self.app.unlock(pin)
        finally:
            self._set_status("")
        if not ok:
            self._set_error("Wrong PIN.")

    def action_quit_app(self):
        self.app.exit()


class ContactItem(ListItem):
    def __init__(
        self,
        name,
        chat_started,
        incoming_request,
        blocked,
        pending,
        clear_pending,
        verified,
        session_established,
        unread_count,
        online=False,
    ):
        parts = []
        if unread_count > 0:
            badge = (
                f"({unread_count})"
                if unread_count < UNREAD_MAX
                else "(99+)"
            )
            parts.append(badge)
        parts.append(name)
        if verified:
            parts.append("*")
        if online and session_established:
            parts.append("●")
        if pending == 2:
            parts.append("[accept?]")
        elif blocked:
            parts.append("[BLOCKED]")
        elif clear_pending:
            parts.append("[clear?]")
        elif pending == 1:
            parts.append("[waiting]")
        elif incoming_request:
            parts.append("[chat req]")
        elif chat_started and session_established:
            parts.append("[active]")
        elif chat_started:
            parts.append("[legacy]")
        label = " ".join(parts)
        self.label_text = label
        super().__init__(Label(label))
        self.contact_name = name


class MainScreen(Screen):
    CSS = """
    #main-layout { height: 1fr; }
    #sidebar {
        width: 38;
        border-right: solid $primary;
        padding: 1;
    }
    #sidebar-title {
        text-align: center;
        text-style: bold;
        color: $accent;
        padding: 0 0 1 0;
    }
    #contacts { height: 1fr; }
    #add-code { margin: 1 0 0 0; }
    #chat-area {
        width: 1fr;
        padding: 0 1;
    }
    #chat-title {
        height: 1;
        text-style: bold;
        color: $accent;
        padding: 0 0 1 0;
    }
    #messages {
        height: 1fr;
        border: solid $primary;
        padding: 0 1;
    }
    #status {
        height: 1;
        color: $warning;
        text-style: italic;
        padding: 0 1;
    }
    #message-input { margin: 1 0; }
    """

    BINDINGS = [
        Binding("ctrl+q", "quit_app", "Quit", show=True),
        Binding("ctrl+l", "lock", "Lock", show=True),
        Binding("m", "open_menu", "Menu", show=True),
        Binding("question_mark", "help", "Help", show=True),
        Binding("ctrl+z", "show_code", "Code", show=True),
        Binding("a", "focus_add", "Add", show=False),
        Binding("i", "add_by_ip", "AddIP", show=False),
        Binding("s", "start_chat", "Start", show=False),
        Binding("y", "accept", "Accept", show=False),
        Binding("x", "reject", "Reject", show=False),
        Binding("c", "clear_chat", "Clear", show=False),
        Binding(
            "d", "delete_contact", "Delete", show=False
        ),
        Binding("t", "stop_chat", "Stop", show=False),
        Binding("v", "verify", "Verify", show=False),
        Binding("ctrl+r", "reset_all", "Reset", show=False),
        Binding("f5", "refresh", "Refresh", show=False),
        Binding("up", "history_prev", "Prev", show=False),
        Binding("down", "history_next", "Next", show=False),
    ]

    def __init__(self):
        super().__init__()
        self.current_contact = None
        self._history = []
        self._history_idx = -1
        self._contacts_items = {}
        self._last_contacts_sig = None
        self._status_tokens = {}

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="main-layout"):
            with Vertical(id="sidebar"):
                yield Static(
                    "Contacts", id="sidebar-title"
                )
                yield ListView(id="contacts")
                yield Input(
                    placeholder="Add by 8-digit code...",
                    id="add-code",
                    max_length=8,
                )
            with Vertical(id="chat-area"):
                yield Static(
                    "Select a contact", id="chat-title"
                )
                yield RichLog(
                    id="messages",
                    markup=False,
                    wrap=True,
                )
                yield Static("", id="status")
                yield Input(
                    placeholder="Message or /command "
                    "(M for menu, ? for help)...",
                    id="message-input",
                )
        yield Footer()

    def on_mount(self):
        self.refresh_contacts(force=True)
        self.load_messages_for(None)
        self.set_interval(1.0, self._tick_presence)

    def set_status(self, msg, token="main"):
        try:
            self._status_tokens[token] = msg
            parts = [
                v for v in self._status_tokens.values() if v
            ]
            self.query_one(
                "#status", Static
            ).update(" · ".join(parts) if parts else "")
        except Exception:
            pass

    def set_chat_title(self, text):
        try:
            self.query_one("#chat-title", Static).update(text)
        except Exception:
            pass

    def _is_online(self, name):
        try:
            ts = self.app._last_heard.get(name, 0)
            return time.time() - ts < ONLINE_WINDOW
        except Exception:
            return False

    def _is_typing(self, name):
        try:
            ts = self.app._peer_typing.get(name, 0)
            return time.time() - ts < TYPING_DISPLAY_TTL
        except Exception:
            return False

    def _tick_presence(self):
        try:
            self.refresh_contacts()
            if self.current_contact:
                self._refresh_chat_title()
        except Exception:
            pass

    def _refresh_chat_title(self):
        if not self.current_contact:
            self.set_chat_title("Select a contact")
            return
        contact = self.app.db.get_contact(
            self.current_contact
        )
        if not contact:
            self.set_chat_title("Select a contact")
            return
        suffix = " *verified" if contact.get("verified") else ""
        if self._is_typing(self.current_contact):
            suffix += " (typing...)"
        elif (
            self._is_online(self.current_contact)
            and contact.get("session_established")
        ):
            suffix += " (online)"
        state = ""
        if contact.get("blocked"):
            state = " [BLOCKED]"
        elif contact.get("pending") == 2:
            state = " [pending your accept]"
        elif contact.get("pending") == 1:
            state = " [waiting for peer]"
        elif contact.get("clear_pending"):
            state = " [peer wants to clear]"
        elif contact.get("chat_started") and contact.get(
            "session_established"
        ):
            state = " [active]"
        elif contact.get("chat_started"):
            state = " [legacy session]"
        self.set_chat_title(
            f"{self.current_contact}{suffix}{state}"
        )

    def _contacts_signature(self):
        sig = []
        for c in self.app.db.get_contacts():
            sig.append(
                (
                    c["name"],
                    c.get("chat_started", 0),
                    c.get("incoming_request", 0),
                    c.get("blocked", 0),
                    c.get("pending", 0),
                    c.get("clear_pending", 0),
                    c.get("verified", 0),
                    c.get("session_established", 0),
                    int(c.get("unread_count", 0)),
                    self._is_online(c["name"]),
                    self._is_typing(c["name"]),
                )
            )
        return tuple(sig)

    def _build_contact_item(self, c):
        return ContactItem(
            c["name"],
            c.get("chat_started", 0),
            c.get("incoming_request", 0),
            c.get("blocked", 0),
            c.get("pending", 0),
            c.get("clear_pending", 0),
            c.get("verified", 0),
            c.get("session_established", 0),
            int(c.get("unread_count", 0)),
            online=self._is_online(c["name"]),
        )

    def refresh_contacts(self, force=False):
        try:
            lv = self.query_one("#contacts", ListView)
        except Exception:
            return
        new_sig = self._contacts_signature()
        if not force and new_sig == self._last_contacts_sig:
            return
        self._last_contacts_sig = new_sig
        contacts = self.app.db.get_contacts()
        new_names = [c["name"] for c in contacts]
        old_names = list(self._contacts_items.keys())
        if not force and new_names == old_names:
            for c in contacts:
                item = self._contacts_items.get(c["name"])
                if item is None:
                    continue
                try:
                    built = self._build_contact_item(c)
                    lbl = item.query_one(Label)
                    lbl.update(built.label_text)
                    item.label_text = built.label_text
                except Exception:
                    continue
            return
        try:
            lv.clear()
        except Exception:
            return
        self._contacts_items = {}
        for c in contacts:
            try:
                item = self._build_contact_item(c)
                lv.append(item)
                self._contacts_items[c["name"]] = item
            except Exception:
                continue
        if self.current_contact:
            for index, name in enumerate(new_names):
                if name == self.current_contact:
                    try:
                        lv.index = index
                    except Exception:
                        pass
                    break

    def load_messages_for(self, contact_name):
        self.current_contact = contact_name
        try:
            log = self.query_one("#messages", RichLog)
        except Exception:
            return
        log.clear()
        if not contact_name:
            self.set_chat_title("Select a contact")
            log.write("Select a contact on the left.")
            return
        contact = self.app.db.get_contact(contact_name)
        if not contact:
            self.set_chat_title("Select a contact")
            return
        self._refresh_chat_title()
        self.app.db.clear_unread(contact_name)
        self.refresh_contacts()
        if contact.get("blocked"):
            log.write("[BLOCKED CONTACT - messages hidden]")
            return
        if contact.get("clear_pending"):
            log.write(
                "[Peer wants to CLEAR the conversation. "
                "Press Y to accept, X to reject.]"
            )
        if not contact.get("verified"):
            log.write(
                "[UNVERIFIED - press V to compare "
                "safety numbers]"
            )
        if not contact.get("session_established"):
            log.write(
                "[No active session - press S or wait "
                "for chat request]"
            )
        for m in self.app.db.get_messages(contact_name):
            ts = time.strftime(
                "%H:%M", time.localtime(m["timestamp"])
            )
            who = (
                "You"
                if m["direction"] == "out"
                else contact_name
            )
            rt = m.get("reply_to", 0)
            ct = m.get("react_to", 0)
            prefix = ""
            if rt:
                prefix = f"[re #{rt}] "
            elif ct:
                prefix = f"[react #{ct}] "
            log.write(
                f"[#{m['id']}] [{ts}] {who}: "
                f"{prefix}{m['content']}"
            )

    def on_list_view_selected(self, event):
        try:
            if isinstance(event.item, ContactItem):
                self.load_messages_for(
                    event.item.contact_name
                )
        except Exception:
            pass

    async def on_input_changed(self, event):
        if event.input.id == "message-input":
            if (
                self.current_contact
                and event.value.strip()
            ):
                asyncio.create_task(
                    self.app.send_typing(
                        self.current_contact
                    )
                )

    async def on_input_submitted(self, event):
        if event.input.id == "add-code":
            code = event.value.strip()
            event.input.value = ""
            if len(code) != 8 or not code.isdigit():
                self.app.notify(
                    "Code must be exactly 8 digits.",
                    severity="error",
                )
                return
            event.input.disabled = True
            self.set_status("Adding...", token="add")
            try:
                await self.app.add_contact_by_code(code)
            except Exception as e:
                self.app.notify(
                    f"Add failed: {e}", severity="error"
                )
            finally:
                self.set_status("", token="add")
                try:
                    event.input.disabled = False
                except Exception:
                    pass
        elif event.input.id == "message-input":
            text = event.value
            if not text.strip():
                return
            event.input.value = ""
            if text.startswith("/"):
                await self.handle_command(text.strip())
                return
            if not self.current_contact:
                self.app.notify(
                    "Select a contact first.",
                    severity="error",
                )
                return
            self._history.append(text)
            if len(self._history) > HISTORY_MAX:
                self._history = self._history[-HISTORY_MAX:]
            self._history_idx = -1
            contact_name = self.current_contact
            asyncio.create_task(
                self._send_bg(contact_name, text)
            )

    async def _send_bg(self, contact_name, text):
        self.set_status("Sending...", token="send")
        ok = False
        try:
            ok = await self.app.send_chat_message(
                contact_name, text
            )
        except Exception as e:
            self.app.notify(
                f"Send failed: {e}", severity="error"
            )
            ok = False
        finally:
            self.set_status("", token="send")
        if not ok:
            try:
                inp = self.query_one(
                    "#message-input", Input
                )
                if not inp.value:
                    inp.value = text
                    try:
                        inp.cursor_position = len(text)
                    except Exception:
                        pass
            except Exception:
                pass

    def _navigate_history(self, direction):
        if not self._history:
            return
        try:
            inp = self.query_one("#message-input", Input)
        except Exception:
            return
        if direction < 0:
            if self._history_idx < 0:
                self._history_idx = len(self._history) - 1
            elif self._history_idx > 0:
                self._history_idx -= 1
            inp.value = self._history[self._history_idx]
        else:
            if (
                self._history_idx >= 0
                and self._history_idx
                < len(self._history) - 1
            ):
                self._history_idx += 1
                inp.value = self._history[self._history_idx]
            else:
                self._history_idx = -1
                inp.value = ""

    def action_history_prev(self):
        try:
            inp = self.query_one("#message-input", Input)
        except Exception:
            return
        if inp.has_focus:
            self._navigate_history(-1)

    def action_history_next(self):
        try:
            inp = self.query_one("#message-input", Input)
        except Exception:
            return
        if inp.has_focus:
            self._navigate_history(1)

    async def handle_command(self, cmd):
        parts = cmd.split(None, 1)
        name = parts[0].lower()
        arg = parts[1].strip() if len(parts) > 1 else ""
        if name == "/help":
            self.action_help()
            return
        if name == "/menu":
            self.action_open_menu()
            return
        if name == "/addip":
            self.action_add_by_ip()
            return
        if name == "/address":
            self.action_show_address()
            return
        if name == "/code":
            self.action_show_code()
            return
        if not self.current_contact:
            self.app.notify(
                "Select a contact first.", severity="error"
            )
            return
        contact = self.app.db.get_contact(
            self.current_contact
        )
        if not contact:
            return
        if name == "/verify":
            self.action_verify()
        elif name == "/find":
            await self._do_find(arg)
        elif name == "/reply":
            await self._do_reply(arg)
        elif name == "/react":
            await self._do_react(arg)
        elif name == "/clear":
            self.action_clear_chat()
        elif name == "/clearall":
            self.action_clear_all()
        elif name == "/stop":
            self.action_stop_chat()
        elif name == "/del":
            if arg:
                try:
                    mid = int(arg)
                except ValueError:
                    self.app.notify(
                        "Usage: /del <id>",
                        severity="error",
                    )
                    return
                self.app.delete_message_confirm(mid)
            else:
                msgs = self.app.db.get_messages(
                    self.current_contact, limit=1
                )
                if not msgs:
                    self.app.notify(
                        "No messages to delete.",
                        severity="error",
                    )
                    return
                self.app.delete_message_confirm(
                    msgs[0]["id"]
                )
        else:
            self.app.notify(
                f"Unknown command: {name}. Try /help.",
                severity="error",
            )

    async def _do_find(self, arg):
        if not arg:
            self.app.notify(
                "Usage: /find <text>", severity="error"
            )
            return
        results = self.app.db.search_messages(
            self.current_contact, arg
        )
        log = self.query_one("#messages", RichLog)
        log.clear()
        log.write(
            f"--- Search: '{arg}' "
            f"({len(results)} matches) ---"
        )
        for m in results:
            ts = time.strftime(
                "%H:%M", time.localtime(m["timestamp"])
            )
            who = (
                "You"
                if m["direction"] == "out"
                else self.current_contact
            )
            log.write(
                f"[#{m['id']}] [{ts}] {who}: "
                f"{m['content']}"
            )

    async def _do_reply(self, arg):
        parts = arg.split(None, 1)
        if len(parts) != 2:
            self.app.notify(
                "Usage: /reply <id> <text>",
                severity="error",
            )
            return
        try:
            target_id = int(parts[0])
        except ValueError:
            self.app.notify(
                "Invalid message ID.", severity="error"
            )
            return
        text = parts[1]
        asyncio.create_task(
            self._send_bg(
                self.current_contact,
                text,
                reply_to=target_id,
            )
        )

    async def _do_react(self, arg):
        parts = arg.split(None, 1)
        if len(parts) != 2:
            self.app.notify(
                "Usage: /react <id> <emoji>",
                severity="error",
            )
            return
        try:
            target_id = int(parts[0])
        except ValueError:
            self.app.notify(
                "Invalid message ID.", severity="error"
            )
            return
        emoji = parts[1]
        asyncio.create_task(
            self._send_bg(
                self.current_contact,
                emoji,
                react_to=target_id,
            )
        )

    async def _send_bg(
        self, contact_name, text, reply_to=0, react_to=0
    ):
        self.set_status("Sending...", token="send")
        ok = False
        try:
            ok = await self.app.send_chat_message(
                contact_name,
                text,
                reply_to=reply_to,
                react_to=react_to,
            )
        except Exception as e:
            self.app.notify(
                f"Send failed: {e}", severity="error"
            )
            ok = False
        finally:
            self.set_status("", token="send")
        if not ok and not reply_to and not react_to:
            try:
                inp = self.query_one(
                    "#message-input", Input
                )
                if not inp.value:
                    inp.value = text
                    try:
                        inp.cursor_position = len(text)
                    except Exception:
                        pass
            except Exception:
                pass

    def action_focus_add(self):
        self.query_one("#add-code", Input).focus()

    def action_add_by_ip(self):
        def on_result(result):
            if result is None:
                return
            ip, port, code = result
            asyncio.create_task(
                self._do_add_by_ip(ip, port, code)
            )

        self.app.push_screen(
            AddByIpScreen(), callback=on_result
        )

    async def _do_add_by_ip(self, ip, port, code):
        self.set_status("Adding by IP...", token="add")
        try:
            await self.app.add_contact_by_ip(
                ip, port, code
            )
        except Exception as e:
            self.app.notify(
                f"Add failed: {e}", severity="error"
            )
        finally:
            self.set_status("", token="add")

    def action_show_address(self):
        ips = get_local_ips()
        self.app.push_screen(
            MyAddressScreen(ips, self.app.tcp_port)
        )

    def action_open_menu(self):
        self.app.push_screen(
            MenuScreen(
                verified_only=self.app.db.get_verified_only(),
                notifications_enabled=(
                    self.app.db.get_notifications_enabled()
                ),
                presence_enabled=(
                    self.app.db.get_presence_enabled()
                ),
            ),
            callback=self._on_menu_result,
        )

    def _on_menu_result(self, action):
        if action is None or action == "close":
            return
        if action in ("start", "accept", "reject"):
            asyncio.create_task(
                self._dispatch_async(action)
            )
        else:
            self._dispatch_sync(action)

    def _dispatch_sync(self, action):
        try:
            if action == "stop":
                self.action_stop_chat()
            elif action == "verify":
                self.action_verify()
            elif action == "clear":
                self.action_clear_chat()
            elif action == "clearall":
                self.action_clear_all()
            elif action == "delete":
                self.action_delete_contact()
            elif action == "code":
                self.action_show_code()
            elif action == "help":
                self.action_help()
            elif action == "lock":
                self.action_lock()
            elif action == "reset":
                self.action_reset_all()
            elif action == "addip":
                self.action_add_by_ip()
            elif action == "address":
                self.action_show_address()
            elif action == "vonl":
                new = not self.app.db.get_verified_only()
                self.app.db.set_verified_only(new)
                self.app.notify(
                    f"Verified-only: "
                    f"{'ON' if new else 'OFF'}"
                )
            elif action == "notif":
                new = (
                    not self.app.db.get_notifications_enabled()
                )
                self.app.db.set_notifications_enabled(new)
                self.app.notify(
                    f"Notifications: "
                    f"{'ON' if new else 'OFF'}"
                )
            elif action == "presence":
                new = (
                    not self.app.db.get_presence_enabled()
                )
                self.app.db.set_presence_enabled(new)
                self.app.notify(
                    f"Presence: "
                    f"{'ON' if new else 'OFF'}"
                )
                if new:
                    asyncio.create_task(
                        self.app.broadcast_presence_now()
                    )
        except Exception as e:
            self.app.notify(
                f"Menu action failed: {e}",
                severity="error",
            )

    async def _dispatch_async(self, action):
        try:
            if action == "start":
                await self.action_start_chat()
            elif action == "accept":
                await self.action_accept()
            elif action == "reject":
                await self.action_reject()
        except Exception as e:
            self.app.notify(
                f"Menu action failed: {e}",
                severity="error",
            )

    def action_help(self):
        self.app.push_screen(HelpScreen())

    def action_show_code(self):
        self.app.push_screen(AddCodeScreen())

    async def action_start_chat(self):
        if not self.current_contact:
            self.app.notify(
                "Select a contact first.", severity="error"
            )
            return
        self.set_status("Starting chat...", token="start")
        try:
            await self.app.start_chat(self.current_contact)
        except Exception as e:
            self.app.notify(
                f"Start failed: {e}", severity="error"
            )
        finally:
            self.set_status("", token="start")

    async def action_accept(self):
        if not self.current_contact:
            self.app.notify(
                "Select a contact first.", severity="error"
            )
            return
        contact = self.app.db.get_contact(
            self.current_contact
        )
        if not contact:
            return
        self.set_status("Accepting...", token="accept")
        try:
            if contact.get("clear_pending"):
                await self.app.accept_clear(
                    self.current_contact
                )
            elif contact.get("pending") == 2:
                await self.app.accept_contact(
                    self.current_contact
                )
            elif contact.get("incoming_request"):
                await self.app.accept_chat(
                    self.current_contact
                )
            else:
                self.app.notify(
                    "Nothing to accept for this contact."
                )
        finally:
            self.set_status("", token="accept")

    async def action_reject(self):
        if not self.current_contact:
            self.app.notify(
                "Select a contact first.", severity="error"
            )
            return
        contact = self.app.db.get_contact(
            self.current_contact
        )
        if not contact:
            return
        self.set_status("Rejecting...", token="reject")
        try:
            if contact.get("clear_pending"):
                await self.app.reject_clear(
                    self.current_contact
                )
            elif contact.get("pending") == 2:
                await self.app.reject_contact(
                    self.current_contact
                )
            elif contact.get("incoming_request"):
                await self.app.reject_chat(
                    self.current_contact
                )
            else:
                self.app.notify(
                    "Nothing to reject for this contact."
                )
        finally:
            self.set_status("", token="reject")

    def action_clear_chat(self):
        if not self.current_contact:
            self.app.notify(
                "Select a contact first.", severity="error"
            )
            return
        self.app.clear_chat_confirm(self.current_contact)

    def action_clear_all(self):
        if not self.current_contact:
            self.app.notify(
                "Select a contact first.", severity="error"
            )
            return
        self.app.clear_all_confirm(self.current_contact)

    def action_delete_contact(self):
        if not self.current_contact:
            self.app.notify(
                "Select a contact first.", severity="error"
            )
            return
        self.app.delete_contact_confirm(
            self.current_contact
        )

    def action_stop_chat(self):
        if not self.current_contact:
            self.app.notify(
                "Select a contact first.", severity="error"
            )
            return
        self.app.stop_chat_confirm(self.current_contact)

    def action_verify(self):
        if not self.current_contact:
            self.app.notify(
                "Select a contact first.", severity="error"
            )
            return
        self.app.show_verify_screen(self.current_contact)

    def action_lock(self):
        asyncio.create_task(self.app.lock())

    def action_reset_all(self):
        self.app.push_screen(
            ConfirmScreen(
                "RESET EVERYTHING?\n"
                "This wipes your identity, contacts, "
                "PIN, audit log and all messages."
            ),
            callback=self._on_reset_confirmed,
        )

    def _on_reset_confirmed(self, confirmed):
        if confirmed:
            asyncio.create_task(self.app.perform_reset())

    def action_refresh(self):
        self.refresh_contacts(force=True)
        if self.current_contact:
            self.load_messages_for(self.current_contact)

    def action_quit_app(self):
        self.app.exit()


class LanMessApp(App):
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
        self._msg_attempts = {}
        self._contact_locks = {}
        self._peer_typing = {}
        self._last_activity = {}
        self._last_heard = {}
        self._last_typing_sent = {}

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

    def _touch_heard(self, name):
        self._last_heard[name] = time.time()

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
        self.db.set_schema_version(7)
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
        if version == "3":
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
            self._audit("MIGRATED_TO_V7")
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
        await self._start_session()
        return True

    async def lock(self):
        self._audit("LOCKED")
        await self._stop_networking()
        self._zero_keys()
        self.user_name = None
        self.tcp_port = None
        self._add_attempts = {}
        self._msg_attempts = {}
        self._contact_locks = {}
        self._peer_typing = {}
        self._last_activity = {}
        self._last_heard = {}
        self._last_typing_sent = {}
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
                    ed_public_to_bytes(
                        self.ed_public
                    ).hex(),
                    x25519_public_to_bytes(
                        self.x25519_public
                    ).hex(),
                    self._current_code_tag,
                )
            )
            self.idle_task = asyncio.create_task(
                self._idle_watchdog()
            )
            self.presence_task = asyncio.create_task(
                self._presence_loop()
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
                await asyncio.sleep(60)
                now = time.time()
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

    async def _send_presence_now(self, contact_name):
        try:
            contact = self.db.get_contact(contact_name)
            if not contact:
                return
            if not contact.get("session_established"):
                return
            ip, port = self._resolve_peer_address(contact)
            if not ip or not port:
                return
            payload = self._signed(
                {
                    "type": "PRESENCE",
                    "from_name": self.user_name,
                    "timestamp": _now_ms(),
                }
            )
            resp = await send_request(
                ip, port, payload, timeout=1.5
            )
            if resp and resp.get("type") == "OK":
                self._touch_heard(contact_name)
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
        contact = self.db.get_contact(contact_name)
        if not contact:
            return
        if not contact.get("session_established"):
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
                ip, port, payload, timeout=1.0
            )
            if resp and resp.get("type") == "OK":
                self._touch_heard(contact_name)
        except Exception:
            pass

    def _current_code_tag(self):
        try:
            code = compute_totp(self.totp_secret)
            return compute_secure_code_tag(
                self.lookup_key, code
            )
        except Exception:
            return ""

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

    async def handle_incoming(self, msg):
        t = msg.get("type")
        try:
            if t == "ADD_REQUEST":
                return await self._handle_add_request(msg)
            if t == "ADD_ACCEPT":
                return await self._handle_add_accept(msg)
            if t == "ADD_REJECT":
                return await self._handle_add_reject(msg)
            if t == "CHAT_START":
                return await self._handle_chat_start(msg)
            if t == "CHAT_ACCEPT":
                return await self._handle_chat_accept(msg)
            if t == "CHAT_REJECT":
                return await self._handle_chat_reject(msg)
            if t == "CHAT_STOP":
                return await self._handle_chat_stop(msg)
            if t == "CLEAR_REQUEST":
                return await self._handle_clear_request(msg)
            if t == "CLEAR_ACCEPT":
                return await self._handle_clear_accept(msg)
            if t == "CLEAR_REJECT":
                return await self._handle_clear_reject(msg)
            if t == "MESSAGE":
                return await self._handle_message(msg)
            if t == "PRESENCE":
                return await self._handle_presence(msg)
            if t == "TYPING":
                return await self._handle_typing(msg)
        except Exception:
            return {"type": "ERROR", "reason": "handler_error"}
        return {"type": "ERROR", "reason": "unknown"}

    async def _handle_add_request(self, msg):
        peer_ip = msg.get("_peer_ip")
        now = time.time()
        if peer_ip:
            last = self._add_attempts.get(peer_ip, 0)
            if now - last < ADD_RATE_LIMIT_SECONDS:
                return {
                    "type": "ADD_REJECT",
                    "reason": "rate_limited",
                }
            self._add_attempts[peer_ip] = now
            self._prune_dict(
                self._add_attempts, ADD_RATE_LIMIT_MAX
            )
        ts = msg.get("timestamp")
        if not self._valid_timestamp(ts):
            return {
                "type": "ADD_REJECT",
                "reason": "stale",
            }
        from_name = msg.get("from_name")
        from_ed = msg.get("from_ed_pub")
        from_x = msg.get("from_x25519_pub")
        from_port = msg.get("from_port")
        challenge_b64 = msg.get("challenge")
        proof_hex = msg.get("proof")
        if not self._valid_name(from_name):
            return {
                "type": "ADD_REJECT",
                "reason": "missing_name",
            }
        if from_name == self.user_name:
            return {
                "type": "ADD_REJECT",
                "reason": "self",
            }
        if not self._valid_hex(from_ed, 32):
            return {
                "type": "ADD_REJECT",
                "reason": "missing_ed_key",
            }
        if not self._valid_hex(from_x, 32):
            return {
                "type": "ADD_REJECT",
                "reason": "missing_x_key",
            }
        if not isinstance(from_port, int) or not (
            1 <= from_port <= 65535
        ):
            from_port = None
        try:
            challenge = base64.b64decode(challenge_b64)
        except Exception:
            return {
                "type": "ADD_REJECT",
                "reason": "bad_challenge",
            }
        if len(challenge) != 32:
            return {
                "type": "ADD_REJECT",
                "reason": "bad_challenge",
            }
        try:
            given_proof = bytes.fromhex(proof_hex)
        except (TypeError, ValueError):
            return {
                "type": "ADD_REJECT",
                "reason": "bad_proof",
            }
        if len(given_proof) != 32:
            return {
                "type": "ADD_REJECT",
                "reason": "bad_proof",
            }
        proof_ok = False
        for offset in (0, -1):
            code = compute_totp(
                self.totp_secret, offset
            )
            expected = hmac.new(
                code.encode("utf-8"),
                b"REQ"
                + from_name.encode("utf-8")
                + challenge,
                hashlib.sha256,
            ).digest()
            if hmac.compare_digest(
                expected, given_proof
            ):
                proof_ok = True
                break
        if not proof_ok:
            self._audit(
                "ADD_INVALID_CODE",
                {"from": from_name},
            )
            return {
                "type": "ADD_REJECT",
                "reason": "invalid_code",
            }
        try:
            from_pk = ed_public_from_bytes(
                bytes.fromhex(from_ed)
            )
        except Exception:
            return {
                "type": "ADD_REJECT",
                "reason": "bad_key",
            }
        if not self._check_signed(msg, from_pk):
            self._audit(
                "ADD_BAD_SIGNATURE",
                {"from": from_name},
            )
            return {
                "type": "ADD_REJECT",
                "reason": "bad_signature",
            }
        self._touch_heard(from_name)
        existing = self.db.get_contact(from_name)
        if existing:
            if existing.get("blocked"):
                return {
                    "type": "ADD_REJECT",
                    "reason": "blocked",
                }
            if existing["ed_public_hex"] != from_ed:
                return {
                    "type": "ADD_REJECT",
                    "reason": "key_mismatch",
                }
        peer = self.discovery.find_by_name(from_name)
        ip = peer["ip"] if peer else peer_ip
        port = peer["tcp_port"] if peer else from_port
        self.db.upsert_contact(
            name=from_name,
            ip=ip,
            port=port,
            ed_public_hex=from_ed,
            x25519_public_hex=from_x,
        )
        self._audit(
            "ADD_REQUEST_RECEIVED", {"from": from_name}
        )
        resp_challenge = os.urandom(32)
        resp_code = compute_totp(self.totp_secret, 0)
        resp_proof = hmac.new(
            resp_code.encode("utf-8"),
            b"ACC"
            + self.user_name.encode("utf-8")
            + resp_challenge,
            hashlib.sha256,
        ).digest()
        resp_fields = {
            "to_name": self.user_name,
            "to_ed_pub": ed_public_to_bytes(
                self.ed_public
            ).hex(),
            "to_x25519_pub": x25519_public_to_bytes(
                self.x25519_public
            ).hex(),
            "challenge": base64.b64encode(
                resp_challenge
            ).decode("ascii"),
            "proof": resp_proof.hex(),
            "timestamp": _now_ms(),
        }
        if existing is None:
            self.db.set_contact_state(
                from_name, pending=2
            )
            self._refresh_main()
            self.notify(
                f"{from_name} wants to add you. "
                "Press Y to accept, X to reject."
            )
            return self._signed(
                {"type": "ADD_PENDING", **resp_fields}
            )
        if existing.get("pending") == 0:
            return self._signed(
                {"type": "ADD_ACCEPT", **resp_fields}
            )
        if existing.get("pending") == 1:
            self.db.set_contact_state(
                from_name, pending=0
            )
            self._refresh_main()
            self.notify(
                f"Mutual add completed with {from_name}."
            )
            self._audit(
                "ADD_MUTUAL", {"contact": from_name}
            )
            return self._signed(
                {"type": "ADD_ACCEPT", **resp_fields}
            )
        self._refresh_main()
        return self._signed(
            {"type": "ADD_PENDING", **resp_fields}
        )

    async def _handle_add_accept(self, msg):
        from_name = msg.get("from_name")
        if not self._valid_name(from_name):
            return {"type": "OK"}
        contact = self.db.get_contact(from_name)
        if not contact:
            return {"type": "OK"}
        from_ed = msg.get("from_ed_pub")
        from_x = msg.get("from_x25519_pub")
        ts = msg.get("timestamp")
        if not self._valid_hex(from_ed, 32):
            return {"type": "OK"}
        if not self._valid_hex(from_x, 32):
            return {"type": "OK"}
        if not self._valid_timestamp(ts):
            return {"type": "OK"}
        if contact["ed_public_hex"] != from_ed:
            self.notify(
                f"Rejected add-accept from {from_name}: "
                "key mismatch.",
                severity="error",
            )
            return {"type": "OK"}
        try:
            peer_pk = ed_public_from_bytes(
                bytes.fromhex(from_ed)
            )
        except Exception:
            return {"type": "OK"}
        if not self._check_signed(msg, peer_pk):
            return {"type": "OK"}
        self._touch_heard(from_name)
        self._apply_peer_ip(msg, from_name)
        if contact.get("pending") in (1, 2):
            self.db.set_contact_state(
                from_name,
                pending=0,
                x25519_public_hex=from_x,
            )
            self._refresh_main()
            self.notify(
                f"{from_name} accepted your add request."
            )
            self._audit(
                "ADD_ACCEPTED", {"contact": from_name}
            )
        return {"type": "OK"}

    async def _handle_add_reject(self, msg):
        from_name = msg.get("from_name")
        if not self._valid_name(from_name):
            return {"type": "OK"}
        contact = self.db.get_contact(from_name)
        if not contact:
            return {"type": "OK"}
        try:
            peer_pk = ed_public_from_bytes(
                bytes.fromhex(contact["ed_public_hex"])
            )
        except Exception:
            return {"type": "OK"}
        if not self._check_signed(msg, peer_pk):
            return {"type": "OK"}
        ts = msg.get("timestamp")
        if not self._valid_timestamp(ts):
            return {"type": "OK"}
        self._touch_heard(from_name)
        self._apply_peer_ip(msg, from_name)
        if contact.get("pending") == 1:
            self.db.delete_contact(from_name)
            self._refresh_main()
            self._refresh_visible_messages()
            self.notify(
                f"{from_name} rejected your add request."
            )
            self._audit(
                "ADD_REJECTED", {"contact": from_name}
            )
        return {"type": "OK"}

    async def _verify_peer_sig(self, msg):
        from_name = msg.get("from_name")
        if not self._valid_name(from_name):
            return None
        contact = self.db.get_contact(from_name)
        if not contact:
            return None
        try:
            pk = ed_public_from_bytes(
                bytes.fromhex(contact["ed_public_hex"])
            )
        except Exception:
            return None
        if not self._check_signed(msg, pk):
            return None
        ts = msg.get("timestamp")
        if not self._valid_timestamp(ts):
            return None
        self._touch_heard(from_name)
        self._apply_peer_ip(msg, from_name)
        contact = self.db.get_contact(from_name)
        return contact

    async def _handle_chat_start(self, msg):
        contact = await self._verify_peer_sig(msg)
        if not contact:
            return {
                "type": "CHAT_REJECT",
                "reason": "invalid",
            }
        if contact.get("blocked"):
            return {
                "type": "CHAT_REJECT",
                "reason": "blocked",
            }
        if contact.get("pending") != 0:
            return {
                "type": "CHAT_REJECT",
                "reason": "pending",
            }
        if (
            self.db.get_verified_only()
            and not contact.get("verified")
        ):
            return {
                "type": "CHAT_REJECT",
                "reason": "unverified",
            }
        try:
            peer_eph_raw = base64.b64decode(
                msg["eph_pub"]
            )
        except Exception:
            return {
                "type": "CHAT_REJECT",
                "reason": "bad_eph",
            }
        if len(peer_eph_raw) != 32:
            return {
                "type": "CHAT_REJECT",
                "reason": "bad_eph",
            }
        if contact.get("chat_started"):
            return {"type": "CHAT_PENDING"}
        self.db.set_contact_state(
            contact["name"],
            incoming_request=1,
            session_peer_eph_pub_hex=peer_eph_raw.hex(),
        )
        self._refresh_main()
        self.notify(
            f"{contact['name']} wants to chat. "
            "Press Y to accept."
        )
        self._audit(
            "CHAT_START_RECEIVED",
            {"contact": contact["name"]},
        )
        return {"type": "CHAT_PENDING"}

    async def _handle_chat_accept(self, msg):
        contact = await self._verify_peer_sig(msg)
        if not contact:
            return {"type": "OK"}
        try:
            peer_eph_raw = base64.b64decode(
                msg["eph_pub"]
            )
        except Exception:
            return {"type": "OK"}
        if len(peer_eph_raw) != 32:
            return {"type": "OK"}
        local_sk_hex = contact.get(
            "session_local_eph_sk_hex", ""
        )
        if not local_sk_hex:
            return {"type": "OK"}
        try:
            local_sk = x25519_private_from_bytes(
                bytes.fromhex(local_sk_hex)
            )
        except Exception:
            return {"type": "OK"}
        try:
            peer_eph_pub = x25519_public_from_bytes(
                peer_eph_raw
            )
            shared = local_sk.exchange(peer_eph_pub)
        except Exception:
            return {"type": "OK"}
        local_eph_pub = x25519_public_to_bytes(
            local_sk.public_key()
        )
        chains = derive_session_chains(
            shared, local_eph_pub, peer_eph_raw
        )
        send_chain = chains[0:32]
        recv_chain = chains[32:64]
        self.db.set_contact_state(
            contact["name"],
            chat_started=1,
            incoming_request=0,
            session_established=1,
            send_chain_key_hex=send_chain.hex(),
            recv_chain_key_hex=recv_chain.hex(),
            send_counter=0,
            recv_counter=0,
            session_local_eph_sk_hex="",
            session_peer_eph_pub_hex="",
        )
        self._touch_activity(contact["name"])
        self._refresh_main()
        self.notify(
            f"Chat started with {contact['name']}."
        )
        self._audit(
            "CHAT_START_ACCEPTED",
            {"contact": contact["name"]},
        )
        asyncio.create_task(
            self._send_presence_now(contact["name"])
        )
        return {"type": "OK"}

    async def _handle_chat_reject(self, msg):
        contact = await self._verify_peer_sig(msg)
        if contact:
            self.notify(
                f"{contact['name']} rejected your chat "
                "request."
            )
        return {"type": "OK"}

    async def _handle_chat_stop(self, msg):
        contact = await self._verify_peer_sig(msg)
        if not contact:
            return {"type": "OK"}
        self.db.set_contact_state(
            contact["name"],
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
        self._last_activity.pop(contact["name"], None)
        self._refresh_main()
        self._refresh_visible_messages()
        self.notify(
            f"{contact['name']} stopped the chat."
        )
        self._audit(
            "CHAT_STOP_RECEIVED",
            {"contact": contact["name"]},
        )
        return {"type": "OK"}

    async def _handle_clear_request(self, msg):
        contact = await self._verify_peer_sig(msg)
        if not contact:
            return {
                "type": "CLEAR_REJECT",
                "reason": "invalid",
            }
        if contact.get("blocked"):
            return {
                "type": "CLEAR_REJECT",
                "reason": "blocked",
            }
        if contact.get("pending") != 0:
            return {
                "type": "CLEAR_REJECT",
                "reason": "pending",
            }
        self.db.set_contact_state(
            contact["name"], clear_pending=1
        )
        self._refresh_main()
        self._refresh_visible_messages()
        self.notify(
            f"{contact['name']} wants to clear the "
            "conversation. Press Y to accept, X to "
            "reject."
        )
        self._audit(
            "CLEAR_REQUEST_RECEIVED",
            {"contact": contact["name"]},
        )
        return {"type": "CLEAR_PENDING"}

    async def _handle_clear_accept(self, msg):
        contact = await self._verify_peer_sig(msg)
        if not contact:
            return {"type": "OK"}
        self.db.clear_messages(contact["name"])
        self.db.set_contact_state(
            contact["name"], clear_pending=0
        )
        self._refresh_main()
        self._refresh_visible_messages()
        self.notify(
            f"{contact['name']} accepted. "
            "Conversation cleared."
        )
        self._audit(
            "CLEAR_ACCEPTED",
            {"contact": contact["name"]},
        )
        return {"type": "OK"}

    async def _handle_clear_reject(self, msg):
        contact = await self._verify_peer_sig(msg)
        if not contact:
            return {"type": "OK"}
        self.db.set_contact_state(
            contact["name"], clear_pending=0
        )
        self.notify(
            f"{contact['name']} declined the clear "
            "request."
        )
        self._audit(
            "CLEAR_REJECTED",
            {"contact": contact["name"]},
        )
        return {"type": "OK"}

    async def _handle_presence(self, msg):
        contact = await self._verify_peer_sig(msg)
        if not contact:
            return {"type": "OK"}
        return {"type": "OK"}

    async def _handle_typing(self, msg):
        contact = await self._verify_peer_sig(msg)
        if not contact:
            return {"type": "OK"}
        self._peer_typing[contact["name"]] = time.time()
        return {"type": "OK"}

    async def _handle_message(self, msg):
        peer_ip = msg.get("_peer_ip")
        now = time.time()
        if peer_ip:
            last = self._msg_attempts.get(peer_ip, 0)
            if now - last < MSG_RATE_LIMIT_SECONDS:
                return {"type": "ERROR", "reason": "rate_limited"}
            self._msg_attempts[peer_ip] = now
            self._prune_dict(
                self._msg_attempts, MSG_RATE_LIMIT_MAX
            )
        from_name = msg.get("from_name")
        if not self._valid_name(from_name):
            return {"type": "ERROR", "reason": "bad_name"}
        contact = self.db.get_contact(from_name)
        if not contact:
            return {"type": "ERROR", "reason": "unknown_contact"}
        if contact.get("blocked"):
            return {"type": "ERROR", "reason": "blocked"}
        if not contact.get("chat_started"):
            return {"type": "ERROR", "reason": "no_chat"}
        if contact.get("pending") != 0:
            return {"type": "ERROR", "reason": "pending"}
        if not contact.get("session_established"):
            return {"type": "ERROR", "reason": "no_session"}
        if (
            self.db.get_verified_only()
            and not contact.get("verified")
        ):
            return {"type": "ERROR", "reason": "unverified"}
        counter = msg.get("counter")
        if (
            not isinstance(counter, int)
            or counter <= 0
            or counter > 2**63 - 1
        ):
            return {"type": "ERROR", "reason": "bad_counter"}
        try:
            nonce = base64.b64decode(msg["nonce"])
            ct = base64.b64decode(msg["ciphertext"])
            sig = base64.b64decode(msg["signature"])
        except Exception:
            return {"type": "ERROR", "reason": "bad_frame"}
        if len(nonce) != 12 or len(ct) < 16 or len(sig) != 64:
            return {"type": "ERROR", "reason": "bad_frame"}
        signed_data = (
            from_name.encode("utf-8")
            + counter.to_bytes(8, "big")
            + nonce
            + ct
        )
        try:
            ed_pk = ed_public_from_bytes(
                bytes.fromhex(contact["ed_public_hex"])
            )
        except Exception:
            return {"type": "ERROR", "reason": "bad_key"}
        if not verify_bytes(ed_pk, sig, signed_data):
            self.db.set_contact_state(
                from_name, blocked=1
            )
            self.notify(
                f"Signature failure from {from_name}. "
                "Contact blocked.",
                severity="error",
            )
            self._audit(
                "SIG_FAILURE", {"contact": from_name}
            )
            self._refresh_main()
            self._refresh_visible_messages()
            return {"type": "ERROR", "reason": "sig_fail"}
        self._touch_heard(from_name)
        recv_counter = contact.get("recv_counter", 0)
        if counter <= recv_counter:
            return {"type": "ERROR", "reason": "replay"}
        recv_chain_hex = contact.get(
            "recv_chain_key_hex", ""
        )
        if not recv_chain_hex:
            return {"type": "ERROR", "reason": "no_chain"}
        try:
            recv_chain = bytes.fromhex(recv_chain_hex)
        except ValueError:
            return {"type": "ERROR", "reason": "bad_chain"}
        gap = counter - recv_counter - 1
        if gap > MAX_CHAIN_GAP:
            return {"type": "ERROR", "reason": "gap_too_big"}
        for _ in range(gap):
            recv_chain = chain_advance(recv_chain)
        msg_key = chain_message_key(recv_chain)
        aad = (
            f"{from_name}:{counter}".encode("utf-8")
        )
        try:
            padded = aes_gcm_decrypt(
                msg_key, nonce, ct, aad
            )
        except Exception:
            self.db.set_contact_state(
                from_name, blocked=1
            )
            self.notify(
                f"Decryption failure from {from_name}. "
                "Contact blocked.",
                severity="error",
            )
            self._audit(
                "DEC_FAILURE", {"contact": from_name}
            )
            self._refresh_main()
            self._refresh_visible_messages()
            return {"type": "ERROR", "reason": "dec_fail"}
        try:
            text = unpad_message(padded).decode(
                "utf-8", errors="replace"
            )
        except Exception:
            return {"type": "ERROR", "reason": "bad_pad"}
        if len(text) > MAX_MESSAGE_LEN:
            text = text[:MAX_MESSAGE_LEN]
        reply_to = int(msg.get("reply_to", 0) or 0)
        react_to = int(msg.get("react_to", 0) or 0)
        new_chain = chain_advance(recv_chain)
        self.db.add_message(
            from_name,
            "in",
            text,
            reply_to=reply_to,
            react_to=react_to,
        )
        self.db.set_contact_state(
            from_name,
            recv_chain_key_hex=new_chain.hex(),
            recv_counter=counter,
        )
        if peer_ip and peer_ip != contact.get("ip"):
            if not contact.get("pinned"):
                self.db.set_contact_state(
                    from_name, ip=peer_ip
                )
        if not self._is_currently_viewing(from_name):
            self.db.increment_unread(from_name)
        self._touch_activity(from_name)
        try:
            enabled = self.db.get_notifications_enabled()
            if react_to:
                notif_body = (
                    f"reacted to #{react_to}: {text}"
                )
            elif reply_to:
                notif_body = (
                    f"re #{reply_to}: {text[:NOTIFY_BODY_MAX]}"
                )
            else:
                notif_body = text[:NOTIFY_BODY_MAX]
            asyncio.create_task(
                asyncio.to_thread(
                    notify,
                    from_name,
                    notif_body,
                    enabled=enabled,
                )
            )
        except Exception:
            pass
        asyncio.create_task(
            self._deferred_refresh(from_name)
        )
        return {"type": "OK"}

    async def _deferred_refresh(self, contact_name):
        try:
            screen = self._get_main_screen()
            if screen is None:
                return
            screen.refresh_contacts()
            if screen.current_contact == contact_name:
                screen.load_messages_for(contact_name)
        except Exception:
            pass

    async def start_chat(self, contact_name):
        contact = self.db.get_contact(contact_name)
        if not contact:
            return
        if contact.get("blocked"):
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
        if contact.get("chat_started"):
            self.notify("Chat is already active.")
            return
        ip, port = self._resolve_peer_address(contact)
        if not ip or not port:
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
    ):
        async with self._get_contact_lock(contact_name):
            contact = self.db.get_contact(contact_name)
            if not contact:
                return False
            if contact.get("blocked"):
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
                self.notify(
                    "Chat not started. Press S to start it.",
                    severity="error",
                )
                return False
            if not contact.get("session_established"):
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
            ip, port = self._resolve_peer_address(contact)
            if not ip or not port:
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
                payload["reply_to"] = int(reply_to)
            if react_to:
                payload["react_to"] = int(react_to)
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
                self.notify(
                    "Message not delivered: no response "
                    "(peer offline or blocking).",
                    severity="error",
                )
                return False
            rtype = resp.get("type")
            if rtype != "OK":
                reason = resp.get("reason", "unknown")
                self.notify(
                    f"Message rejected by peer: {reason}",
                    severity="error",
                )
                return False
            self.db.add_message(
                contact_name,
                "out",
                text,
                reply_to=reply_to,
                react_to=react_to,
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
        if contact.get("blocked"):
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
            self._last_typing_sent.pop(
                contact_name, None
            )
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
        self._msg_attempts = {}
        self._contact_locks = {}
        self._peer_typing = {}
        self._last_activity = {}
        self._last_heard = {}
        self._last_typing_sent = {}
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