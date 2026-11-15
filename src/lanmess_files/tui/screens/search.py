import time

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container
from textual.screen import ModalScreen
from textual.widgets import Input, Label, ListItem, ListView, Static

from ...config import SEARCH_LIMIT


class SearchScreen(ModalScreen):
    CSS = """
    SearchScreen { align: center middle; }
    #search-box {
        width: 80;
        height: 80%;
        border: thick $accent;
        padding: 1 2;
        background: $surface;
    }
    #search-title {
        text-align: center;
        text-style: bold;
        color: $accent;
        padding: 0 0 1 0;
    }
    #search-input { margin: 0 0 1 0; }
    #search-results {
        height: 1fr;
        border: solid $primary;
    }
    """

    BINDINGS = [
        Binding("escape", "close", "Close", show=False),
    ]

    def compose(self) -> ComposeResult:
        with Container(id="search-box"):
            yield Static("Search All Messages", id="search-title")
            yield Input(
                placeholder="Type to search...",
                id="search-input",
            )
            yield ListView(id="search-results")

    def on_mount(self):
        self.query_one("#search-input", Input).focus()

    def on_input_changed(self, event):
        if event.input.id == "search-input":
            query = event.value.strip()
            lv = self.query_one("#search-results", ListView)
            lv.clear()
            if not query:
                return
            results = self.app.db.search_all_messages(
                query, limit=SEARCH_LIMIT
            )
            for m in results:
                ts = time.strftime(
                    "%Y-%m-%d %H:%M",
                    time.localtime(m["timestamp"]),
                )
                text = (
                    f"[{m['contact_name']}] [{ts}] "
                    f"{m['content']}"
                )
                if len(text) > 100:
                    text = text[:97] + "..."
                lv.append(ListItem(Label(text)))

    def action_close(self):
        self.dismiss()