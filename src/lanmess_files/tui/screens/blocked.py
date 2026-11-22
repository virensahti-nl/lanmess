import asyncio

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Static


class BlockedScreen(ModalScreen):
    CSS = """
    BlockedScreen { align: center middle; }
    #blocked-box {
        width: 72;
        height: 70%;
        border: thick $accent;
        padding: 2 3;
        background: $surface;
    }
    #blocked-title {
        text-align: center;
        text-style: bold;
        color: $accent;
        padding: 0 0 1 0;
    }
    #blocked-list {
        height: 1fr;
        border: solid $primary;
        padding: 0 1;
    }
    #blocked-list Button {
        width: 100%;
        margin: 0 0 1 0;
    }
    #blocked-close {
        width: 100%;
        margin: 1 0 0 0;
    }
    """

    BINDINGS = [
        Binding("escape", "close", "Close", show=False),
    ]

    def compose(self) -> ComposeResult:
        with Container(id="blocked-box"):
            yield Static(
                "Blocked Contacts", id="blocked-title"
            )
            yield VerticalScroll(id="blocked-list")
            yield Button(
                "Close", id="blocked-close",
                variant="primary",
            )

    def on_mount(self):
        self._refresh()

    def _refresh(self):
        try:
            scroll = self.query_one(
                "#blocked-list", VerticalScroll
            )
        except Exception:
            return
        for child in list(scroll.children):
            try:
                child.remove()
            except Exception:
                pass
        try:
            blocked = self.app.db.get_blocked()
        except Exception:
            blocked = []
        if not blocked:
            scroll.mount(
                Static(
                    "No blocked contacts.\n"
                    "Use /block to block the selected "
                    "contact."
                )
            )
            return
        for entry in blocked:
            name = entry.get("name", "?")
            ed = entry.get("ed_public_hex", "")
            preview = ed[:16] + "..." if ed else "?"
            btn = Button(
                f"Unblock {name}   [{preview}]",
                id=f"unblockbtn-{name}",
                variant="warning",
            )
            btn.blocked_name = name
            scroll.mount(btn)

    def on_button_pressed(self, event):
        bid = event.button.id or ""
        if bid == "blocked-close":
            self.dismiss()
            return
        name = getattr(event.button, "blocked_name", None)
        if name:
            asyncio.create_task(self._do_unblock(name))

    async def _do_unblock(self, name):
        try:
            await self.app.unblock_contact(name)
        finally:
            self._refresh()

    def action_close(self):
        self.dismiss()