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

You type the group code once. From now on you unlock with your PIN.

## Adding contacts

Two ways:

- **By code** (`A` or the add-code input): the peer must be on the same
  broadcast domain. LANMess discovers them via a UDP beacon, then performs
  the signed add handshake.
- **By IP** (`I` or `/addip`): you provide the peer's IP, port, and current
  add code. No discovery is used. Works on any routable network, including
  overlay networks and VPNs.

To find your own addresses, use `Show my address` in the menu (`Session`
section) or `/address`. Every IPv4 on the machine is listed with the TCP
port peers should connect to.

## UI overview

- Sidebar: contacts with unread badges `(3)`, verified markers `*`, and
  state tags `[active]`, `[chat req]`, `[BLOCKED]`.
- Chat pane: conversation, `[UNVERIFIED]` warning if applicable, status line,
  message input.
- `M` opens a sectioned menu (Chat / History / Session / System).
- `Ctrl+Z` opens a modal with your current add code and countdown.
- `?` opens help. `Ctrl+L` locks. `Ctrl+Q` quits.
- `I` opens the add-by-IP dialog.

## Security model (v1.1.8)

- Per-session X25519 handshake with fresh ephemerals both sides.
- Symmetric hash ratchet per message (forward secrecy within a session).
- Ed25519 signatures on every control frame and every message.
- Length-padded messages (256-byte blocks).
- Safety numbers for out-of-band verification (`V` or `/verify`).
- Data at rest sealed by a random per-device master wrapped with Argon2id(PIN).
- HMAC-chained audit log for sensitive events.
- Frame size caps, connection semaphore, per-IP rate limits.

## Migrating

From v1.1.3 through v1.1.6: enter your PIN. Everything re-encrypts under a
fresh random master if needed and the audit log is created. Nothing lost.

From v1.1.2: enter your old group code once plus a new PIN.

See THREAT_MODEL.md for what is and isn't defended.