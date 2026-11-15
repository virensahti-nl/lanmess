from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Static


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
                yield Button(
                    "Set Panic Password",
                    id="m-panic",
                    variant="error",
                )
                yield Static("Session", classes="menu-section")
                yield Button(
                    "Show my address", id="m-address"
                )
                yield Button(
                    "Show add code (Ctrl+Z)", id="m-code"
                )
                yield Button(
                    "Rotate Keys", id="m-rotate", variant="warning"
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