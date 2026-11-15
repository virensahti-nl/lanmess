import asyncio
import time

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import (
    Button,
    Footer,
    Header,
    Input,
    Label,
    ListView,
    RichLog,
    Static,
)

from ..config import (
    HISTORY_MAX,
    ONLINE_WINDOW,
    TYPING_DISPLAY_TTL,
)
from .contact_item import ContactItem
from .helpers import get_local_ips
from .screens import (
    AddByIpScreen,
    AddCodeScreen,
    ConfirmScreen,
    HelpScreen,
    MenuScreen,
    MyAddressScreen,
    PanicSettingsScreen,
    SearchScreen,
)


class MainScreen(Screen):
    CSS = """
    #main-layout { height: 1fr; }
    #sidebar {
        width: 38;
        border-right: solid $primary;
        padding: 1;
    }
    #sidebar-title {
        text-align: center;
        text-style: bold;
        color: $accent;
        padding: 0 0 1 0;
    }
    #contacts { height: 1fr; }
    #add-code { margin: 1 0 0 0; }
    #chat-area {
        width: 1fr;
        padding: 0 1;
    }
    #chat-title {
        height: 1;
        text-style: bold;
        color: $accent;
        padding: 0 0 1 0;
    }
    #messages {
        height: 1fr;
        border: solid $primary;
        padding: 0 1;
    }
    #status {
        height: 1;
        color: $warning;
        text-style: italic;
        padding: 0 1;
    }
    #message-input { margin: 1 0; }
    """

    BINDINGS = [
        Binding("ctrl+q", "quit_app", "Quit", show=True),
        Binding("ctrl+l", "lock", "Lock", show=True),
        Binding("ctrl+f", "search", "Search", show=True),
        Binding("m", "open_menu", "Menu", show=True),
        Binding("question_mark", "help", "Help", show=True),
        Binding("ctrl+z", "show_code", "Code", show=True),
        Binding("a", "focus_add", "Add", show=False),
        Binding("i", "add_by_ip", "AddIP", show=False),
        Binding("s", "start_chat", "Start", show=False),
        Binding("y", "accept", "Accept", show=False),
        Binding("x", "reject", "Reject", show=False),
        Binding("c", "clear_chat", "Clear", show=False),
        Binding(
            "d", "delete_contact", "Delete", show=False
        ),
        Binding("t", "stop_chat", "Stop", show=False),
        Binding("v", "verify", "Verify", show=False),
        Binding("ctrl+r", "reset_all", "Reset", show=False),
        Binding("f5", "refresh", "Refresh", show=False),
        Binding("up", "history_prev", "Prev", show=False),
        Binding("down", "history_next", "Next", show=False),
    ]

    def __init__(self):
        super().__init__()
        self.current_contact = None
        self._history = []
        self._history_idx = -1
        self._contacts_items = {}
        self._last_contacts_sig = None
        self._status_tokens = {}

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="main-layout"):
            with Vertical(id="sidebar"):
                yield Static(
                    "Contacts", id="sidebar-title"
                )
                yield ListView(id="contacts")
                yield Input(
                    placeholder="Add by 8-digit code...",
                    id="add-code",
                    max_length=8,
                )
            with Vertical(id="chat-area"):
                yield Static(
                    "Select a contact", id="chat-title"
                )
                yield RichLog(
                    id="messages",
                    markup=False,
                    wrap=True,
                )
                yield Static("", id="status")
                yield Input(
                    placeholder="Message or /command "
                    "(M for menu, ? for help)...",
                    id="message-input",
                )
        yield Footer()

    def on_mount(self):
        self.refresh_contacts(force=True)
        self.load_messages_for(None)
        self.set_interval(1.0, self._tick_presence)

    def set_status(self, msg, token="main"):
        try:
            self._status_tokens[token] = msg
            parts = [
                v for v in self._status_tokens.values() if v
            ]
            self.query_one(
                "#status", Static
            ).update(" · ".join(parts) if parts else "")
        except Exception:
            pass

    def set_chat_title(self, text):
        try:
            self.query_one("#chat-title", Static).update(text)
        except Exception:
            pass

    def _is_online(self, name):
        try:
            now = time.time()
            heard = self.app._last_heard.get(name, 0)
            offline = self.app._peer_offline.get(name, 0)
            if offline > heard:
                return False
            return now - heard < ONLINE_WINDOW
        except Exception:
            return False

    def _is_typing(self, name):
        try:
            ts = self.app._peer_typing.get(name, 0)
            return time.time() - ts < TYPING_DISPLAY_TTL
        except Exception:
            return False

    def _tick_presence(self):
        try:
            self.refresh_contacts()
            if self.current_contact:
                self._refresh_chat_title()
        except Exception:
            pass

    def _refresh_chat_title(self):
        if not self.current_contact:
            self.set_chat_title("Select a contact")
            return
        contact = self.app.db.get_contact(
            self.current_contact
        )
        if not contact:
            self.set_chat_title("Select a contact")
            return
        suffix = " *verified" if contact.get("verified") else ""
        if self._is_typing(self.current_contact):
            suffix += " (typing...)"
        elif (
            self._is_online(self.current_contact)
            and contact.get("session_established")
        ):
            suffix += " (online)"
        state = ""
        if contact.get("blocked"):
            state = " [BLOCKED]"
        elif contact.get("pending") == 2:
            state = " [pending your accept]"
        elif contact.get("pending") == 1:
            state = " [waiting for peer]"
        elif contact.get("clear_pending"):
            state = " [peer wants to clear]"
        elif contact.get("chat_started") and contact.get(
            "session_established"
        ):
            state = " [active]"
        elif contact.get("chat_started"):
            state = " [legacy session]"
        self.set_chat_title(
            f"{self.current_contact}{suffix}{state}"
        )

    def _contacts_signature(self):
        sig = []
        for c in self.app.db.get_contacts():
            sig.append(
                (
                    c["name"],
                    c.get("chat_started", 0),
                    c.get("incoming_request", 0),
                    c.get("blocked", 0),
                    c.get("pending", 0),
                    c.get("clear_pending", 0),
                    c.get("verified", 0),
                    c.get("session_established", 0),
                    int(c.get("unread_count", 0)),
                    self._is_online(c["name"]),
                    self._is_typing(c["name"]),
                )
            )
        return tuple(sig)

    def _build_contact_item(self, c):
        return ContactItem(
            c["name"],
            c.get("chat_started", 0),
            c.get("incoming_request", 0),
            c.get("blocked", 0),
            c.get("pending", 0),
            c.get("clear_pending", 0),
            c.get("verified", 0),
            c.get("session_established", 0),
            int(c.get("unread_count", 0)),
            online=self._is_online(c["name"]),
            typing=self._is_typing(c["name"]),
        )

    def refresh_contacts(self, force=False):
        try:
            lv = self.query_one("#contacts", ListView)
        except Exception:
            return
        new_sig = self._contacts_signature()
        if not force and new_sig == self._last_contacts_sig:
            return
        self._last_contacts_sig = new_sig
        contacts = self.app.db.get_contacts()
        new_names = [c["name"] for c in contacts]
        old_names = list(self._contacts_items.keys())
        if not force and new_names == old_names:
            for c in contacts:
                item = self._contacts_items.get(c["name"])
                if item is None:
                    continue
                try:
                    built = self._build_contact_item(c)
                    lbl = item.query_one(Label)
                    lbl.update(built.label_text)
                    item.label_text = built.label_text
                except Exception:
                    continue
            return
        try:
            lv.clear()
        except Exception:
            return
        self._contacts_items = {}
        for c in contacts:
            try:
                item = self._build_contact_item(c)
                lv.append(item)
                self._contacts_items[c["name"]] = item
            except Exception:
                continue
        if self.current_contact:
            for index, name in enumerate(new_names):
                if name == self.current_contact:
                    try:
                        lv.index = index
                    except Exception:
                        pass
                    break

    def load_messages_for(self, contact_name):
        self.current_contact = contact_name
        try:
            log = self.query_one("#messages", RichLog)
        except Exception:
            return
        log.clear()
        if not contact_name:
            self.set_chat_title("Select a contact")
            log.write("Select a contact on the left.")
            return
        contact = self.app.db.get_contact(contact_name)
        if not contact:
            self.set_chat_title("Select a contact")
            return
        self._refresh_chat_title()
        self.app.db.clear_unread(contact_name)
        self.refresh_contacts()
        if contact.get("blocked"):
            log.write("[BLOCKED CONTACT - messages hidden]")
            return
        if contact.get("clear_pending"):
            log.write(
                "[Peer wants to CLEAR the conversation. "
                "Press Y to accept, X to reject.]"
            )
        if not contact.get("verified"):
            log.write(
                "[UNVERIFIED - press V to compare "
                "safety numbers]"
            )
        if not contact.get("session_established"):
            log.write(
                "[No active session - press S or wait "
                "for chat request]"
            )
        for m in self.app.db.get_messages(contact_name):
            ts = time.strftime(
                "%H:%M", time.localtime(m["timestamp"])
            )
            who = (
                "You"
                if m["direction"] == "out"
                else contact_name
            )
            rt = m.get("reply_to", 0)
            ct = m.get("react_to", 0)
            prefix = ""
            if rt:
                prefix = f"[re #{rt}] "
            elif ct:
                prefix = f"[react #{ct}] "
            log.write(
                f"[#{m['id']}] [{ts}] {who}: "
                f"{prefix}{m['content']}"
            )

    def on_list_view_selected(self, event):
        try:
            if isinstance(event.item, ContactItem):
                self.load_messages_for(
                    event.item.contact_name
                )
        except Exception:
            pass

    async def on_input_changed(self, event):
        if event.input.id == "message-input":
            if (
                self.current_contact
                and event.value.strip()
            ):
                asyncio.create_task(
                    self.app.send_typing(
                        self.current_contact
                    )
                )

    async def on_input_submitted(self, event):
        if event.input.id == "add-code":
            code = event.value.strip()
            event.input.value = ""
            if len(code) != 8 or not code.isdigit():
                self.app.notify(
                    "Code must be exactly 8 digits.",
                    severity="error",
                )
                return
            event.input.disabled = True
            self.set_status("Adding...", token="add")
            try:
                await self.app.add_contact_by_code(code)
            except Exception as e:
                self.app.notify(
                    f"Add failed: {e}", severity="error"
                )
            finally:
                self.set_status("", token="add")
                try:
                    event.input.disabled = False
                except Exception:
                    pass
        elif event.input.id == "message-input":
            text = event.value
            if not text.strip():
                return
            event.input.value = ""
            if text.startswith("/"):
                await self.handle_command(text.strip())
                return
            if not self.current_contact:
                self.app.notify(
                    "Select a contact first.",
                    severity="error",
                )
                return
            self._history.append(text)
            if len(self._history) > HISTORY_MAX:
                self._history = self._history[-HISTORY_MAX:]
            self._history_idx = -1
            contact_name = self.current_contact
            asyncio.create_task(
                self._send_bg(contact_name, text)
            )

    def _navigate_history(self, direction):
        if not self._history:
            return
        try:
            inp = self.query_one("#message-input", Input)
        except Exception:
            return
        if direction < 0:
            if self._history_idx < 0:
                self._history_idx = len(self._history) - 1
            elif self._history_idx > 0:
                self._history_idx -= 1
            inp.value = self._history[self._history_idx]
        else:
            if (
                self._history_idx >= 0
                and self._history_idx
                < len(self._history) - 1
            ):
                self._history_idx += 1
                inp.value = self._history[self._history_idx]
            else:
                self._history_idx = -1
                inp.value = ""

    def action_history_prev(self):
        try:
            inp = self.query_one("#message-input", Input)
        except Exception:
            return
        if inp.has_focus:
            self._navigate_history(-1)

    def action_history_next(self):
        try:
            inp = self.query_one("#message-input", Input)
        except Exception:
            return
        if inp.has_focus:
            self._navigate_history(1)

    async def handle_command(self, cmd):
        parts = cmd.split(None, 1)
        name = parts[0].lower()
        arg = parts[1].strip() if len(parts) > 1 else ""
        if name == "/help":
            self.action_help()
            return
        if name == "/menu":
            self.action_open_menu()
            return
        if name == "/addip":
            self.action_add_by_ip()
            return
        if name == "/address":
            self.action_show_address()
            return
        if name == "/code":
            self.action_show_code()
            return
        if not self.current_contact:
            self.app.notify(
                "Select a contact first.", severity="error"
            )
            return
        contact = self.app.db.get_contact(
            self.current_contact
        )
        if not contact:
            return
        if name == "/verify":
            self.action_verify()
        elif name == "/find":
            await self._do_find(arg)
        elif name == "/reply":
            await self._do_reply(arg)
        elif name == "/react":
            await self._do_react(arg)
        elif name == "/clear":
            self.action_clear_chat()
        elif name == "/clearall":
            self.action_clear_all()
        elif name == "/stop":
            self.action_stop_chat()
        elif name == "/del":
            if arg:
                try:
                    mid = int(arg)
                except ValueError:
                    self.app.notify(
                        "Usage: /del <id>",
                        severity="error",
                    )
                    return
                self.app.delete_message_confirm(mid)
            else:
                msgs = self.app.db.get_messages(
                    self.current_contact, limit=1
                )
                if not msgs:
                    self.app.notify(
                        "No messages to delete.",
                        severity="error",
                    )
                    return
                self.app.delete_message_confirm(
                    msgs[0]["id"]
                )
        else:
            self.app.notify(
                f"Unknown command: {name}. Try /help.",
                severity="error",
            )

    async def _do_find(self, arg):
        if not arg:
            self.app.notify(
                "Usage: /find <text>", severity="error"
            )
            return
        results = self.app.db.search_messages(
            self.current_contact, arg
        )
        log = self.query_one("#messages", RichLog)
        log.clear()
        log.write(
            f"--- Search: '{arg}' "
            f"({len(results)} matches) ---"
        )
        for m in results:
            ts = time.strftime(
                "%H:%M", time.localtime(m["timestamp"])
            )
            who = (
                "You"
                if m["direction"] == "out"
                else self.current_contact
            )
            log.write(
                f"[#{m['id']}] [{ts}] {who}: "
                f"{m['content']}"
            )

    async def _do_reply(self, arg):
        parts = arg.split(None, 1)
        if len(parts) != 2:
            self.app.notify(
                "Usage: /reply <id> <text>",
                severity="error",
            )
            return
        try:
            target_id = int(parts[0])
        except ValueError:
            self.app.notify(
                "Invalid message ID.", severity="error"
            )
            return
        text = parts[1]
        asyncio.create_task(
            self._send_bg(
                self.current_contact,
                text,
                reply_to=target_id,
            )
        )

    async def _do_react(self, arg):
        parts = arg.split(None, 1)
        if len(parts) != 2:
            self.app.notify(
                "Usage: /react <id> <emoji>",
                severity="error",
            )
            return
        try:
            target_id = int(parts[0])
        except ValueError:
            self.app.notify(
                "Invalid message ID.", severity="error"
            )
            return
        emoji = parts[1]
        asyncio.create_task(
            self._send_bg(
                self.current_contact,
                emoji,
                react_to=target_id,
            )
        )

    async def _send_bg(
        self, contact_name, text, reply_to=0, react_to=0
    ):
        self.set_status("Sending...", token="send")
        ok = False
        try:
            ok = await self.app.send_chat_message(
                contact_name,
                text,
                reply_to=reply_to,
                react_to=react_to,
            )
        except Exception as e:
            self.app.notify(
                f"Send failed: {e}", severity="error"
            )
            ok = False
        finally:
            self.set_status("", token="send")
        if not ok and not reply_to and not react_to:
            try:
                inp = self.query_one(
                    "#message-input", Input
                )
                if not inp.value:
                    inp.value = text
                    try:
                        inp.cursor_position = len(text)
                    except Exception:
                        pass
            except Exception:
                pass

    def action_focus_add(self):
        self.query_one("#add-code", Input).focus()

    def action_add_by_ip(self):
        def on_result(result):
            if result is None:
                return
            ip, port, code = result
            asyncio.create_task(
                self._do_add_by_ip(ip, port, code)
            )

        self.app.push_screen(
            AddByIpScreen(), callback=on_result
        )

    async def _do_add_by_ip(self, ip, port, code):
        self.set_status("Adding by IP...", token="add")
        try:
            await self.app.add_contact_by_ip(
                ip, port, code
            )
        except Exception as e:
            self.app.notify(
                f"Add failed: {e}", severity="error"
            )
        finally:
            self.set_status("", token="add")

    def action_show_address(self):
        ips = get_local_ips()
        self.app.push_screen(
            MyAddressScreen(ips, self.app.tcp_port)
        )

    def action_search(self):
        self.app.push_screen(SearchScreen())

    def action_open_menu(self):
        self.app.push_screen(
            MenuScreen(
                verified_only=self.app.db.get_verified_only(),
                notifications_enabled=(
                    self.app.db.get_notifications_enabled()
                ),
                presence_enabled=(
                    self.app.db.get_presence_enabled()
                ),
            ),
            callback=self._on_menu_result,
        )

    def _on_menu_result(self, action):
        if action is None or action == "close":
            return
        if action in ("start", "accept", "reject"):
            asyncio.create_task(
                self._dispatch_async(action)
            )
        elif action == "panic":
            self._do_set_panic()
        elif action == "rotate":
            self._do_rotate_keys()
        else:
            self._dispatch_sync(action)

    def _do_set_panic(self):
        def on_result(pin):
            if pin is not None:
                self.app.db.set_panic_pin(pin)
                if pin:
                    self.app.notify("Panic PIN set.")
                else:
                    self.app.notify("Panic PIN removed.")
        self.app.push_screen(
            PanicSettingsScreen(), callback=on_result
        )

    def _do_rotate_keys(self):
        self.app.push_screen(
            ConfirmScreen(
                "Rotate keys?\n"
                "This generates new identity keys and sends "
                "a signed ROTATE frame to all contacts."
            ),
            callback=lambda ok: asyncio.create_task(
                self.app.rotate_keys()
            ) if ok else None,
        )

    def _dispatch_sync(self, action):
        try:
            if action == "stop":
                self.action_stop_chat()
            elif action == "verify":
                self.action_verify()
            elif action == "clear":
                self.action_clear_chat()
            elif action == "clearall":
                self.action_clear_all()
            elif action == "delete":
                self.action_delete_contact()
            elif action == "code":
                self.action_show_code()
            elif action == "help":
                self.action_help()
            elif action == "lock":
                self.action_lock()
            elif action == "reset":
                self.action_reset_all()
            elif action == "addip":
                self.action_add_by_ip()
            elif action == "address":
                self.action_show_address()
            elif action == "vonl":
                new = not self.app.db.get_verified_only()
                self.app.db.set_verified_only(new)
                self.app.notify(
                    f"Verified-only: "
                    f"{'ON' if new else 'OFF'}"
                )
            elif action == "notif":
                new = (
                    not self.app.db.get_notifications_enabled()
                )
                self.app.db.set_notifications_enabled(new)
                self.app.notify(
                    f"Notifications: "
                    f"{'ON' if new else 'OFF'}"
                )
            elif action == "presence":
                new = (
                    not self.app.db.get_presence_enabled()
                )
                self.app.db.set_presence_enabled(new)
                self.app.notify(
                    f"Presence: "
                    f"{'ON' if new else 'OFF'}"
                )
                if new:
                    asyncio.create_task(
                        self.app.broadcast_presence_now()
                    )
                else:
                    asyncio.create_task(
                        self.app.broadcast_offline_now()
                    )
        except Exception as e:
            self.app.notify(
                f"Menu action failed: {e}",
                severity="error",
            )

    async def _dispatch_async(self, action):
        try:
            if action == "start":
                await self.action_start_chat()
            elif action == "accept":
                await self.action_accept()
            elif action == "reject":
                await self.action_reject()
        except Exception as e:
            self.app.notify(
                f"Menu action failed: {e}",
                severity="error",
            )

    def action_help(self):
        self.app.push_screen(HelpScreen())

    def action_show_code(self):
        self.app.push_screen(AddCodeScreen())

    async def action_start_chat(self):
        if not self.current_contact:
            self.app.notify(
                "Select a contact first.", severity="error"
            )
            return
        self.set_status("Starting chat...", token="start")
        try:
            await self.app.start_chat(self.current_contact)
        finally:
            self.set_status("", token="start")

    async def action_accept(self):
        if not self.current_contact:
            self.app.notify(
                "Select a contact first.", severity="error"
            )
            return
        contact = self.app.db.get_contact(
            self.current_contact
        )
        if not contact:
            return
        self.set_status("Accepting...", token="accept")
        try:
            if contact.get("clear_pending"):
                await self.app.accept_clear(
                    self.current_contact
                )
            elif contact.get("pending") == 2:
                await self.app.accept_contact(
                    self.current_contact
                )
            elif contact.get("incoming_request"):
                await self.app.accept_chat(
                    self.current_contact
                )
            else:
                self.app.notify(
                    "Nothing to accept for this contact."
                )
        finally:
            self.set_status("", token="accept")

    async def action_reject(self):
        if not self.current_contact:
            self.app.notify(
                "Select a contact first.", severity="error"
            )
            return
        contact = self.app.db.get_contact(
            self.current_contact
        )
        if not contact:
            return
        self.set_status("Rejecting...", token="reject")
        try:
            if contact.get("clear_pending"):
                await self.app.reject_clear(
                    self.current_contact
                )
            elif contact.get("pending") == 2:
                await self.app.reject_contact(
                    self.current_contact
                )
            elif contact.get("incoming_request"):
                await self.app.reject_chat(
                    self.current_contact
                )
            else:
                self.app.notify(
                    "Nothing to reject for this contact."
                )
        finally:
            self.set_status("", token="reject")

    def action_clear_chat(self):
        if not self.current_contact:
            self.app.notify(
                "Select a contact first.", severity="error"
            )
            return
        self.app.clear_chat_confirm(self.current_contact)

    def action_clear_all(self):
        if not self.current_contact:
            self.app.notify(
                "Select a contact first.", severity="error"
            )
            return
        self.app.clear_all_confirm(self.current_contact)

    def action_delete_contact(self):
        if not self.current_contact:
            self.app.notify(
                "Select a contact first.", severity="error"
            )
            return
        self.app.delete_contact_confirm(
            self.current_contact
        )

    def action_stop_chat(self):
        if not self.current_contact:
            self.app.notify(
                "Select a contact first.", severity="error"
            )
            return
        self.app.stop_chat_confirm(self.current_contact)

    def action_verify(self):
        if not self.current_contact:
            self.app.notify(
                "Select a contact first.", severity="error"
            )
            return
        self.app.show_verify_screen(self.current_contact)

    def action_lock(self):
        asyncio.create_task(self.app.lock())

    def action_reset_all(self):
        self.app.push_screen(
            ConfirmScreen(
                "RESET EVERYTHING?\n"
                "This wipes your identity, contacts, "
                "PIN, audit log and all messages."
            ),
            callback=self._on_reset_confirmed,
        )

    def _on_reset_confirmed(self, confirmed):
        if confirmed:
            asyncio.create_task(self.app.perform_reset())

    def action_refresh(self):
        self.refresh_contacts(force=True)
        if self.current_contact:
            self.load_messages_for(self.current_contact)

    def action_quit_app(self):
        self.app.exit()