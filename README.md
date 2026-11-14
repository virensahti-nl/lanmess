<<<<<<< HEAD
<div align="center">
  <h1>LANMess</h1>
  <p><strong>Serverless, end-to-end encrypted, terminal-based messenger for your LAN and beyond.</strong></p>

  [![PyPI Version](https://img.shields.io/pypi/v/lanmess.svg)](https://pypi.org/project/lanmess/)
  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
  [![Python Versions](https://img.shields.io/pypi/pyversions/lanmess.svg)](https://pypi.org/project/lanmess/)
</div>

---

**LANMess** is a secure, serverless, peer-to-peer messenger that runs entirely in your terminal. It automatically discovers peers on your local network or connects directly via IP (perfect for Tailscale, WireGuard, or routed LANs). All messages are end-to-end encrypted, and your local database is protected by a PIN and Argon2id.

No servers. No cloud. No telemetry. Just pure, encrypted communication.

## Features

- **Zero-Knowledge Architecture:** Messages are encrypted with per-pair X25519 ECDH keys and AES-256-GCM. Ed25519 signatures prevent forgery.
- **Serverless Discovery:** Automatically finds peers on the same broadcast domain using UDP multicast beacons.
- **Tailscale / VPN Ready:** Add peers by IP and Port. Pinned addresses survive LAN changes and automatically route over your VPN.
- **Data at Rest:** Your entire database (messages, contacts, identity) is encrypted using a random per-device master key, wrapped with your PIN via Argon2id.
- **Panic Password:** Configure a secondary PIN that instantly wipes your local database and exits the app if you are ever forced to unlock your device.
- **Key Rotation:** Compromised your keys? Rotate them seamlessly and notify your contacts via signed control frames.
- **Auto-Reconnect & Outbox:** If a peer goes offline, your messages queue up. When they return, the session re-negotiates automatically and the outbox flushes.
- **Live Presence & Typing:** See who is online (`●`) and when they are typing.
- **Global Search UI:** Press `Ctrl+F` to search across all your messages and contacts.
- **Cross-Platform Notifications:** Natively supports Linux, macOS, Windows, and Termux.
- **Rich TUI:** A beautiful terminal interface with unread badges, replies, reactions, and command history.

## Installation

Requires **Python 3.9** or higher.

```bash
pip install lanmess
```

## Quick Start

Start the application:
```bash
lanmess
```

### First Launch
1. **Display Name:** Choose a name (e.g., `alice`).
2. **Group Code:** A shared secret (min 12 chars). All peers must use the same group code to discover each other.
3. **PIN:** A strong PIN to unlock your local database.

*Note: You only type the group code once. From then on, you unlock the app with your PIN.*

## Adding Contacts

- **By Code (`A`):** Best for local LANs. Automatically finds the peer via broadcast discovery using their temporary 8-digit Add Code (`Ctrl+Z`).
- **By IP (`I`):** Best for Tailscale or routed networks. Enter the peer's IP, Port, and Add Code manually. 

*Add-by-IP addresses are **pinned**. They will not be overwritten if the peer's local LAN IP changes.*

## Interface & Shortcuts

### Global Keys
| Key | Action |
| :--- | :--- |
| `M` | Open the main action menu |
| `?` | Show help |
| `Ctrl+Z` | Show your 8-digit Add Code |
| `Ctrl+F` | Search all messages |
| `Ctrl+L` | Lock the app (requires PIN to unlock) |
| `Ctrl+Q` | Quit |

### Chat Shortcuts
| Key | Action |
| :--- | :--- |
| `A` | Focus the "Add by Code" input |
| `S` | Start or Reconnect a chat |
| `Y` / `X` | Accept / Reject chat requests |
| `C` / `D` | Clear history / Delete contact |
| `T` | Stop the current chat session |
| `V` | Verify contact safety numbers |
| `Up` / `Down` | Navigate your message history |

### Slash Commands
| Command | Action |
| :--- | :--- |
| `/help` | Show help |
| `/find <text>` | Search messages with the current contact |
| `/reply <id> <text>` | Reply to a specific message |
| `/react <id> <emoji>` | React to a specific message |
| `/clear` | Clear local history |
| `/clearall` | Ask the peer to clear the history on both sides |
| `/stop` | Stop the chat session |
| `/del <id>` | Delete a specific message |

## Security Model

LANMess is designed to be secure against passive network observers and casual device access. 

- **Signatures:** Every control frame (Add, Chat, Clear, Presence, Typing, Rotate) is signed with Ed25519.
- **Forward Secrecy:** Session chains use a symmetric hash ratchet. Old chain keys are deleted from memory after use.
- **Padding:** Messages are padded to 256-byte blocks to prevent length inference.
- **Safety Numbers:** TOFU (Trust On First Use) is mitigated by displaying a 60-digit safety number. Press `V` to verify your peers out-of-band.
- **Audit Log:** All security-relevant events (failed PINs, key rotations, signature failures) are stored in an HMAC-chained audit log inside your encrypted database.

For a full breakdown of what is and isn't defended (including traffic analysis and compromised peers), please read [THREAT_MODEL.md](THREAT_MODEL.md).

## Development

To develop locally, clone the repo and install in editable mode with test dependencies:

```bash
git clone https://github.com/yourname/lanmess.git
cd lanmess
pip install -e ".[test]"
```

Run the test suite (251 tests):
```bash
pytest
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
=======
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

## v1.1.10 features

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

From v1.1.3 through v1.1.9: enter your PIN. Nothing lost.

See THREAT_MODEL.md for what is and isn't defended.
>>>>>>> 92032534049ad11f9b247214e95cce07d24c9883
