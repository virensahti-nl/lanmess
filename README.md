# LANMess

LAN-only end-to-end encrypted messenger with a terminal UI.

## Install

pip install lanmess

## Run

lanmess

## First launch

1. Display name.
2. Group code (min 12 chars, shared with your peers).
3. PIN (min 12 chars, mixed character classes). This unlocks your local database.

You type the group code once. From now on you unlock with your PIN.

## UI overview

- Sidebar shows contacts with unread badges `(3)`, verified markers `*`, and state tags `[active]`, `[chat req]`, `[BLOCKED]`.
- Chat pane shows the conversation, a `[UNVERIFIED]` warning if applicable, a status line, and the message input.
- `M` opens a sectioned menu (Chat / History / Session / System).
- `Ctrl+Z` opens a modal with your current add code and countdown.
- `?` opens help. `Ctrl+L` locks. `Ctrl+Q` quits.

## Security model (v1.1.6)

- Per-session X25519 handshake with fresh ephemerals both sides.
- Symmetric hash ratchet per message (forward secrecy within a session).
- Ed25519 signatures on every control frame and every message.
- Length-padded messages (256-byte blocks).
- Safety numbers for out-of-band verification (`V` or `/verify`).
- Data at rest sealed by a random per-device master wrapped with Argon2id(PIN).
- HMAC-chained audit log for sensitive events.
- Frame size caps, connection semaphore, per-IP rate limits.

## Migrating

From v1.1.3 / v1.1.4 / v1.1.5: enter your PIN. Everything re-encrypts under a
fresh random master if needed and the audit log is created. Nothing lost.

From v1.1.2: enter your old group code once plus a new PIN.

See THREAT_MODEL.md for what is and isn't defended.