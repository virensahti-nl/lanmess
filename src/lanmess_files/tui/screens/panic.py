from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Static


class PanicSettingsScreen(ModalScreen):
    CSS = """
    PanicSettingsScreen { align: center middle; }
    #panic-box {
        width: 60;
        height: auto;
        border: thick $error;
        padding: 2 3;
        background: $surface;
    }
    #panic-title {
        text-align: center;
        text-style: bold;
        color: $error;
        padding: 0 0 1 0;
    }
    #panic-note {
        text-align: center;
        color: $text-muted;
        padding: 0 0 1 0;
    }
    PanicSettingsScreen Input { margin: 0 0 1 0; }
    PanicSettingsScreen Button {
        width: 100%;
        margin: 0 0 1 0;
    }
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=False),
    ]

    def compose(self) -> ComposeResult:
        with Container(id="panic-box"):
            yield Static("Panic Password", id="panic-title")
            yield Static(
                "Enter a secondary password. If you enter this "
                "password at the login screen, the database will "
                "be instantly wiped and the app will exit.\n"
                "Leave blank to disable.",
                id="panic-note",
            )
            yield Input(
                placeholder="New Panic PIN",
                password=True,
                id="panic-pin",
            )
            yield Button(
                "Set Panic PIN", id="panic-set", variant="error"
            )
            yield Button(
                "Cancel", id="panic-cancel", variant="primary"
            )

    def on_button_pressed(self, event):
        if event.button.id == "panic-cancel":
            self.dismiss(None)
            return
        if event.button.id == "panic-set":
            pin = self.query_one("#panic-pin", Input).value
            self.dismiss(pin)

    def action_cancel(self):
        self.dismiss(None)