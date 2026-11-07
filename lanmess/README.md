# LANMess

End-to-end encrypted messenger with a terminal UI. Discovers peers on the
local LAN, or add them by IP and port to use any network you can route to.

## Install

pip install lanmess

## Run

lanmess

## First launch

1. Display name.
2. Group code (min 12 chars, shared with your peers).
3. PIN (min 12 chars, mixed character classes). Unlocks your local database.

## Adding contacts

- **By code** (`A`): the peer must be on the same broadcast domain.
- **By IP** (`I`): peer's IP, port, and current add code. Works on any routable
  network.

Addresses from add-by-IP are pinned: they will not be overwritten by
`_apply_peer_ip` when the peer's LAN address changes. Add-by-code contacts
are not pinned.

## v1.1.9 features

- Manual IP pinning: typed addresses survive LAN visits.
- Session idle timeout: 10 minutes of inactivity ends the session.
- PIN brute-force lockout: 5 failures -> 30s, 10 -> 5min, 20 -> 1h, 50 -> 24h.
- Verified-only mode: reject chats with unverified contacts (menu toggle).
- Message search: `/find <text>`.
- Cross-platform notifications: notify-send, termux-notification,
  terminal-notifier, osascript, PowerShell, or terminal bell.
- Presence and typing indicators (opt-in, menu toggle).
- Replies (`/reply <id> <text>`) and reactions (`/react <id> <emoji>`).
- Command history: up/down in the message input.

## UI overview

- Sidebar: contacts with unread badges `(3)`, verified markers `*`, and state
  tags `[active]`, `[chat req]`, `[BLOCKED]`.
- `M` opens a sectioned menu (Chat / History / Privacy / Session / System).
- `Ctrl+Z` opens a modal with your current add code.
- `I` opens the add-by-IP dialog. `?` opens help. `Ctrl+L` locks. `Ctrl+Q` quits.

## Migrating

From v1.1.3 through v1.1.8: enter your PIN. Nothing lost.

See THREAT_MODEL.md for what is and isn't defended.