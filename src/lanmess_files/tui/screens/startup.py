import asyncio

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container
from textual.screen import Screen
from textual.widgets import Button, Input, Static

from ...config import (
    APP_NAME,
    APP_VERSION,
    MAX_GROUP_CODE_LEN,
    MIN_GROUP_CODE_LEN,
    PIN_MIN_LEN,
)
from ..helpers import _check_pin_strength
from .confirm import ConfirmScreen


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
                        f"PIN (min {PIN_MIN_LEN}, all of "
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
                    "Migrating to v1.1.13. Enter your old "
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
        if self.db.check_panic_pin(pin):
            await self.app.panic_wipe()
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