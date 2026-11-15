from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Static

from ..helpers import _valid_ipv4, _valid_port


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