# LANMess

<p align="center">
  <a href="https://pypi.org/project/lanmess/"><img src="https://img.shields.io/pypi/v/lanmess.svg" alt="PyPI"></a>
  <a href="https://pypi.org/project/lanmess/"><img src="https://img.shields.io/pypi/pyversions/lanmess.svg" alt="Python"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT"></a>
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows%20%7C%20termux-lightgrey" alt="Platform">
</p>

<p align="center">
  <a href="https://pypi.org/project/lanmess/"><b>Install</b></a> ·
  <a href="#quick-start"><b>Quick Start</b></a> ·
  <a href="#features"><b>Features</b></a> ·
  <a href="THREAT_MODEL.md"><b>Threat Model</b></a> ·
  <a href="SECURITY.md"><b>Security</b></a> ·
  <a href="#contributing"><b>Contributing</b></a>
</p>

A serverless, end-to-end encrypted, terminal-based messenger for local networks and routed overlays.

LANMess discovers peers on the same broadcast domain over UDP, connects directly over TCP, and encrypts every message end-to-end with per-session X25519 ECDH and a symmetric hash ratchet. The local SQLite database is encrypted at rest under a random per-device master key, wrapped with your PIN via Argon2id.

No accounts. No phone numbers. No central server. No telemetry. No cloud.

## Features

- **End-to-end encryption.** X25519 ECDH for session setup; AES-256-GCM for message payloads. Every control frame is signed with Ed25519.
- **Forward secrecy.** One-way HMAC-SHA256 ratchet per session. Old chain keys are erased after use.
- **Encrypted local storage.** The entire database is encrypted under a random per-device master key, recoverable only via Argon2id(PIN).
- **Serverless discovery.** UDP broadcast beacons with rotating TOTP-derived code tags. No registry, no directory.
- **Add by code or by IP.** Works on a LAN with broadcast discovery, or across routed overlays like Tailscale, WireGuard, and ZeroTier.
- **Tamper-evident audit log.** HMAC-chained security events inside the encrypted database.
- **PIN lockout and panic password.** Exponential lockout on failed attempts; a secondary password wipes the database on demand.
- **Key rotation.** Rotate Ed25519 and X25519 keys without re-adding contacts.
- **Terminal UI.** Contact list, chat log, unread badges, message history, slash commands, global search.
- **Cross-platform notifications.** Linux, macOS, Windows, and Termux.

## Installation

LANMess requires Python 3.9 or later.

Install from PyPI:

```bash
pip install lanmess
```

Or from source:

```bash
git clone https://github.com/virensahti-nl/lanmess.git
cd lanmess
python -m pip install -e ".[test]"
```

Verify the install:

```bash
lanmess --version
```

## Quick Start

Launch the app:

```bash
lanmess
```

On first launch you will be asked for:

1. **Display name.** Shown to peers. 1 to 40 characters, no control characters.
2. **Group code.** A shared secret of at least 12 characters. All peers that should discover and add each other must use the same group code. It is used once to derive shared keys and never stored in plaintext.
3. **PIN.** A strong PIN of at least 12 characters, containing at least three of: lowercase, uppercase, digit, symbol. Used to unlock the local database.

The group code is only entered once. From then on, you unlock the app with your PIN.

### Adding a contact

1. On the peer's machine, press `Ctrl+Z` to reveal the current 8-digit add code.
2. On your machine, enter that code in the "Add by 8-digit code" field.
3. For routed networks, press `I` and enter the peer's IP, port, and code instead.

### Starting a chat

1. Select the contact in the left sidebar.
2. Press `S` to send a chat request. The peer presses `Y` to accept.
3. Once a session is established, type messages in the input field and press Enter.

Press `?` inside the app for the full list of shortcuts and slash commands.

## Interface

### Global keys

| Key | Action |
| --- | --- |
| `M` | Open the action menu |
| `?` | Show help |
| `Ctrl+Z` | Show your 8-digit add code |
| `Ctrl+F` | Search all messages |
| `Ctrl+L` | Lock the app |
| `Ctrl+Q` | Quit |

### Chat shortcuts

| Key | Action |
| --- | --- |
| `A` | Focus the add-by-code input |
| `I` | Add by IP |
| `S` | Start or reconnect a chat |
| `Y` / `X` | Accept / reject a chat or add request |
| `C` / `D` | Clear history / delete contact |
| `T` | Stop the current chat session |
| `V` | Verify contact safety numbers |
| `Up` / `Down` | Navigate message history |

### Slash commands

| Command | Action |
| --- | --- |
| `/help` | Show help |
| `/menu` | Open the action menu |
| `/addip` | Add by IP and port |
| `/address` | Show your IPs and port |
| `/code` | Show your add code |
| `/verify` | Show the safety number for the current contact |
| `/find <text>` | Search messages with the current contact |
| `/reply <id> <text>` | Reply to a specific message |
| `/react <id> <emoji>` | React to a specific message |
| `/clear` | Clear local history with the current contact |
| `/clearall` | Ask the peer to clear the history on both sides |
| `/stop` | Stop the chat session |
| `/del <id>` | Delete a specific message |
| `/del` | Delete the most recent message |

## Security

The cryptographic primitives are Ed25519, X25519, AES-256-GCM, HKDF-SHA256, HMAC-SHA256, PBKDF2-HMAC-SHA256, and Argon2id. Message bodies are padded to 256-byte blocks to hide plaintext length. Database rows are bound to their context via AAD so ciphertexts cannot be swapped between rows.

LANMess defends against passive network observers, active network attackers without keys, replay, database theft, PIN brute-force, and offline brute-force of the panic password. It does **not** defend against a rooted device while unlocked, traffic analysis, a compromised peer, or a first-contact man-in-the-middle without out-of-band safety-number verification. It has not been independently audited.

The full threat model is in [`THREAT_MODEL.md`](THREAT_MODEL.md). Reporting information and known limitations are in [`SECURITY.md`](SECURITY.md).

## Configuration and Storage

| Path | Purpose |
| --- | --- |
| `~/.lanmess/` | Base directory, mode `0700` |
| `~/.lanmess/lanmess.db` | Encrypted SQLite database, mode `0600` |
| `~/.lanmess/lanmess.db-wal` | SQLite WAL file |
| `~/.lanmess/lanmess.db-shm` | SQLite shared memory file |
| `~/.lanmess/lanmess.db-journal` | SQLite rollback journal |

| Port | Protocol | Purpose |
| --- | --- | --- |
| `50505/udp` | UDP broadcast | Discovery beacons |
| `50510-50600/tcp` | TCP | Peer-to-peer control and message frames |

The TCP port is chosen on first launch from the range and stored in the encrypted identity record. If the port is already in use on startup, a new one is selected automatically.

To back up LANMess, copy `~/.lanmess/lanmess.db` (and the `-wal` and `-shm` files while the app is running) to a secure location. The backup is useless without the PIN.

## Development

Clone the repository and install in editable mode:

```bash
git clone https://github.com/virensahti-nl/lanmess.git
cd lanmess
python -m venv .venv
source .venv/bin/activate    # On Windows: .venv\Scripts\activate
python -m pip install -e ".[test]"
```

Run the app locally:

```bash
python -m lanmess_files.main
```

### Project layout

```
lanmess/
├── pyproject.toml
├── README.md
├── THREAT_MODEL.md
├── SECURITY.md
├── LICENSE
├── src/
│   └── lanmess_files/
│       ├── __init__.py
│       ├── config.py
│       ├── crypto.py
│       ├── database.py
│       ├── discovery.py
│       ├── network.py
│       ├── notifications.py
│       ├── tui.py
│       └── main.py
└── tests/
    ├── conftest.py
    └── test_*.py
```

### Testing

```bash
pytest
```

The suite covers the cryptographic primitives, KDFs, ratchets, padding, database migrations, audit log chaining, lockout and panic flows, discovery, network framing, protocol handlers, notifications, and outbox behavior.

## Contributing

Issues and pull requests are welcome. Please:

- Open an issue before a large change so the design can be discussed.
- Include a test for any behavioral change.
- Run `pytest` before opening a pull request.
- For anything security-related, follow the note in [`SECURITY.md`](SECURITY.md).

## License

MIT. See [`LICENSE`](LICENSE).

LANMess is provided as-is, without warranty of any kind. Review the threat model before relying on it for sensitive communication.