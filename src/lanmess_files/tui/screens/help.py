from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container
from textual.screen import ModalScreen
from textual.widgets import Button, Static

from ...config import APP_VERSION


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
            yield Static(
                f"Help - LANMess v{APP_VERSION}",
                id="help-title",
            )
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
                "  /older         Load older messages\n"
                "  /del <id>      Delete message #id\n"
                "  /del           Delete most recent\n"
                "  /block         Block current contact\n"
                "  /unblock <n>   Unblock a name\n"
                "  /blocked       Show blocked list\n"
                "  /changepin     Change unlock PIN\n"
                "  /rotations     List pending rotations\n"
                "  /version       Show version\n"
                "\n"
                "Keys:\n"
                "  M          Open menu\n"
                "  I          Add by IP\n"
                "  Ctrl+F     Search all messages\n"
                "  Ctrl+Z     Show add code\n"
                "  Ctrl+L     Lock\n"
                "  Ctrl+Q     Quit\n"
                "  ?          This help\n"
                "  A/S/Y/X    Add/Start/Accept/Reject\n"
                "  C/D/T/V    Clear/Delete/Stop/Verify\n"
                "  Up/Down    Message history\n"
                "  PageUp     Load older messages\n"
                "\n"
                "Security (v1.1.13):\n"
                "  Per-session X25519 + hash ratchet.\n"
                "  Ed25519 signatures on every frame\n"
                "  (including reply and reaction ids).\n"
                "  256-byte padding on messages.\n"
                "  Safety numbers for identity proof.\n"
                "  Random per-device master wrapped\n"
                "  with Argon2id(PIN).\n"
                "  HMAC-chained audit log.\n"
                "  PIN lockout after 5 failures.\n"
                "  Persistent blocking (survives delete).\n"
                "  Auto-lock after configurable idle.\n"
                "  Key Rotation via signed frames.\n"
                "  Panic Password (Argon2id-hashed).\n"
                "  Automatic outbox retry queue.",
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