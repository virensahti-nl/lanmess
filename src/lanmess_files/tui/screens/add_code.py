from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container
from textual.screen import ModalScreen
from textual.widgets import Button, Static

from ...crypto import compute_totp, totp_remaining


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