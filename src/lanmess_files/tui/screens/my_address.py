from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container
from textual.screen import ModalScreen
from textual.widgets import Button, Static


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