from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Static


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