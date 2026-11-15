from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Static


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