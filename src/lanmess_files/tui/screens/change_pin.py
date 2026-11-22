from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Static

from ..helpers import _check_pin_strength


class ChangePinScreen(ModalScreen):
    CSS = """
    ChangePinScreen { align: center middle; }
    #changepin-box {
        width: 60;
        height: auto;
        border: thick $accent;
        padding: 2 3;
        background: $surface;
    }
    #changepin-title {
        text-align: center;
        text-style: bold;
        color: $accent;
        padding: 0 0 1 0;
    }
    #changepin-note {
        text-align: center;
        color: $text-muted;
        padding: 0 0 1 0;
    }
    ChangePinScreen Input { margin: 0 0 1 0; }
    #changepin-error {
        color: $error;
        height: auto;
        padding: 0 0 1 0;
        text-align: center;
    }
    ChangePinScreen Button {
        width: 100%;
        margin: 0 0 1 0;
    }
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=False),
    ]

    def compose(self) -> ComposeResult:
        with Container(id="changepin-box"):
            yield Static(
                "Change PIN", id="changepin-title"
            )
            yield Static(
                "Enter your current PIN and choose a "
                "new one. The new PIN must meet the same "
                "strength requirements as the original.",
                id="changepin-note",
            )
            yield Input(
                placeholder="Current PIN",
                password=True,
                id="cp-old",
            )
            yield Input(
                placeholder="New PIN",
                password=True,
                id="cp-new",
            )
            yield Input(
                placeholder="Confirm new PIN",
                password=True,
                id="cp-confirm",
            )
            yield Static("", id="changepin-error")
            yield Button(
                "Change PIN",
                id="cp-apply",
                variant="primary",
            )
            yield Button(
                "Cancel",
                id="cp-cancel",
                variant="default",
            )

    def _set_error(self, msg):
        try:
            self.query_one(
                "#changepin-error", Static
            ).update(msg)
        except Exception:
            pass

    def on_button_pressed(self, event):
        if event.button.id == "cp-cancel":
            self.dismiss(None)
            return
        if event.button.id != "cp-apply":
            return
        old = self.query_one("#cp-old", Input).value
        new = self.query_one("#cp-new", Input).value
        confirm = self.query_one(
            "#cp-confirm", Input
        ).value
        if not old:
            self._set_error("Current PIN required.")
            return
        err = _check_pin_strength(new)
        if err:
            self._set_error(err)
            return
        if new != confirm:
            self._set_error("New PINs do not match.")
            return
        self.dismiss((old, new))

    def action_cancel(self):
        self.dismiss(None)