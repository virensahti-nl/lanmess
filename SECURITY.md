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

## Scope

Reports about the cryptographic protocol, the network handlers, the database encryption, the panic password, or the PIN lockout are in scope. Traffic analysis, rooted devices, and missing features that are already listed as non-goals in the threat model are out of scope.