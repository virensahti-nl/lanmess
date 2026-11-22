# Security

If you think you have found a security issue in LANMess, open an issue at:

https://github.com/virensahti-nl/lanmess/issues

Describe what you found, how to reproduce it, and which version you are running. Do not post working exploit code publicly; describe the problem and a maintainer will ask for more details if needed.

Nothing here is a commitment to respond, fix, or disclose on any particular timeline.

## What LANMess Protects Against

A short summary. The full treatment is in [`THREAT_MODEL.md`](THREAT_MODEL.md).

- Message contents against a passive observer on the local network or overlay.
- Active network attackers who do not have the keys.
- Replay and reordering of captured frames.
- Someone who has stolen the encrypted database file but does not know the PIN.
- Offline brute-force of the PIN and the panic password.
- Repeated add-request attempts from the same peer name or the same IP address.
- Messages and chat-start requests from blocked peers, including peers who have been deleted from the contact list but remain on the blocklist.

## What LANMess Does Not Protect Against

- A rooted or unlocked device while the app is running.
- Traffic analysis or metadata correlation.
- A compromised peer device after the peer has decrypted a message.
- A first-contact man-in-the-middle attack if the two peers have not compared safety numbers out-of-band.
- Supply-chain compromise of Python, `cryptography`, or `argon2-cffi`.
- Side-channel attacks on the CPU or memory.

LANMess has not been independently audited. Do not rely on it for communication where a compromise would cause serious harm.

## Known Limitations

- No post-compromise security. The symmetric hash ratchet provides forward secrecy within a session, but a device compromised while a session is active can read future messages in that session.
- No metadata resistance. An observer can see who is talking, when, and how often.
- No decoy vault. The panic password wipes the database. It does not open a fake conversation history.
- Best-effort secure deletion. SQLite overwrites deleted pages with `secure_delete=ON`, but the underlying storage may retain old data. Use full-disk encryption if this matters.
- Blocking is local. A blocked peer is refused service by this device. Other peers on the same network are not affected.

## The Panic Password

The panic password is a secondary password that, when entered at the unlock screen, zeroes the master key in memory, wipes the database, deletes the SQLite WAL, SHM, and journal files, and exits the app. This provides a way to destroy local state under coercion.

Storage format:

- `panic_pin_salt`: 16 random bytes, generated fresh each time the panic password is set or changed.
- `panic_pin_hash`: the string `v10:` followed by Base64 of `nonce (12 bytes) || AES-256-GCM ciphertext of a 32-byte all-zero marker, authenticated under `key = Argon2id(panic_pin, panic_pin_salt)` with AAD `b"lanmess-panic-v1"`.

Verification requires, in order:

1. Running Argon2id with t=3, m=64 MiB, p=4 to derive the key from the candidate PIN and the stored salt.
2. Passing the 128-bit AES-GCM authentication tag.
3. Matching the recovered marker against the fixed 32-byte constant via `hmac.compare_digest`.

No raw Argon2id output is stored. The panic PIN cannot be recovered from the database without brute-forcing Argon2id and passing GCM authentication for every candidate. This is the same cost as guessing the vault PIN.

Legacy panic password values from v1.1.12 are hex-encoded Argon2id outputs. `check_panic_pin` falls back to the legacy comparison when the stored value does not carry the `v10:` prefix, so an upgrade does not lock anyone out. Re-setting the panic password (or setting a new one) writes the v10 format automatically.

## Blocking

Blocking in v1.1.13 is persistent. When a peer is blocked:

- Any active chat is stopped.
- The contact record is marked `blocked = 1`.
- An entry is written to the `blocked` table, keyed by the peer's name hash and encrypted under the local master key.
- Every subsequent control frame from that peer (`ADD_REQUEST`, `ADD_ACCEPT`, `ROTATE`, `CHAT_START`, `CHAT_ACCEPT`, `CHAT_STOP`, `CLEAR_*`, `MESSAGE`, `PRESENCE`, `TYPING`) is rejected before any state is touched.
- If the local contact record is deleted, the blocked entry remains. A blocked peer cannot be re-added by code or by IP until they are unblocked.

Unblocking removes the entry from the `blocked` table and clears `blocked` on the contact record if one exists. The peer can then be re-added as normal.

Contacts that were auto-blocked by v1.1.11 through no fault of their own, with no audit entry recording a `BLOCKED_LOCAL` event and no pending state, are unblocked automatically on first unlock after the upgrade to v1.1.13. The change is written to the audit chain as `UNBLOCKED_UPGRADE`.

## Reporting an Issue

Open a GitHub issue with:

- A description of the behavior you observed.
- Steps to reproduce.
- The version
- Operating system and Python version.

For anything that looks like a cryptographic flaw or a bypass, describe the problem but do not include working exploit code. A maintainer will ask for more details if needed.

## Scope

Reports about the cryptographic protocol, the network handlers, the database encryption, the panic password, the PIN lockout, or the persistent blocklist are in scope. Traffic analysis, rooted devices, and missing features that are already listed as non-goals in the threat model are out of scope.