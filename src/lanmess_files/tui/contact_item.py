from textual.widgets import Label, ListItem

from ..config import UNREAD_MAX


class ContactItem(ListItem):
    def __init__(
        self,
        name,
        chat_started,
        incoming_request,
        blocked,
        pending,
        clear_pending,
        verified,
        session_established,
        unread_count,
        online=False,
        typing=False,
    ):
        parts = []
        if unread_count > 0:
            badge = (
                f"({unread_count})"
                if unread_count < UNREAD_MAX
                else "(99+)"
            )
            parts.append(badge)
        parts.append(name)
        if verified:
            parts.append("*")
        if online and session_established:
            parts.append("●")
        if typing and session_established:
            parts.append("(typing)")
        if pending == 2:
            parts.append("[accept?]")
        elif blocked:
            parts.append("[BLOCKED]")
        elif clear_pending:
            parts.append("[clear?]")
        elif pending == 1:
            parts.append("[waiting]")
        elif incoming_request:
            parts.append("[chat req]")
        elif chat_started and session_established:
            parts.append("[active]")
        elif chat_started:
            parts.append("[legacy]")
        label = " ".join(parts)
        self.label_text = label
        super().__init__(Label(label))
        self.contact_name = name