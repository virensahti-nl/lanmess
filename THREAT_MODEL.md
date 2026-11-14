# Threat Model

This document outlines the security guarantees of LANMess, what it defends against, what it explicitly does not defend against, and the roadmap for future security improvements.

## Defended Against

### Data in Transit
- **Passive LAN Observer:** Message content and control payloads are encrypted with AES-256-GCM. A passive sniffer on the network only sees ciphertext.
- **Active LAN Attacker (No Keys):** Every frame is signed with Ed25519. An attacker cannot forge, modify, or inject messages without the sender's private key.
- **Replay Attacks:** Monotonic counters and a one-way symmetric hash ratchet ensure that captured messages cannot be replayed or decrypted out of order.
- **First-Contact MITM (With Group Code):** The add-contact handshake requires a TOTP-based challenge-response. Knowing the group code is not enough to impersonate a peer without the active 8-digit code.
- **Beacon Brute-Force:** The `code_tag` broadcast over UDP is HMACed with a lookup key derived from the group code. An attacker cannot reverse the tag to discover the active TOTP or the peer's name.
- **Message-Length Inference:** All messages are padded to 256-byte blocks before encryption, hiding the exact plaintext length.

### Data at Rest
- **Stolen Database File:** The entire SQLite database is encrypted. The master key is a random 32-byte value per device, recoverable only via Argon2id(PIN). An attacker with the `.db` file cannot read anything without the PIN.
- **Row Tampering:** Every database row is encrypted with AES-GCM and bound to its specific context using AAD (Additional Authenticated Data). You cannot swap ciphertexts between rows or tables.
- **Audit Log Tampering:** Security events are stored in an HMAC-chained audit log. Modifying, deleting, or reordering any entry breaks the chain and is detected.

### Operational Security
- **Brute-Force PIN Guessing:** The local unlock process enforces an exponential lockout (5 fails = 30s, 20 fails = 1 hour, 50 fails = 24 hours).
- **Compromised Device (Coercion):** A secondary "Panic Password" can be configured. Entering it at the login screen instantly zeroes the master key in memory, wipes the database, deletes the SQLite WAL/SHM files, and exits the app silently.
- **Key Compromise (Rotation):** Users can trigger a Key Rotation from the menu. This generates new Ed25519/X25519 keys and broadcasts a signed `ROTATE` frame to all contacts, allowing them to update their records without the "delete and re-add" dance.
- **Connection Floods / DoS:** The TCP server is protected by a connection semaphore, per-IP rate limits, and strict frame-size caps (64 KB). Slow-loris attacks are mitigated by read timeouts.

## Not Defended Against

- **Rooted or Unlocked Device (While Logged In):** If an attacker has physical access to your device *while the app is unlocked and running*, they can read in-memory keys and plaintext messages.
- **Coerced PIN (Without Panic Mode):** If you are forced to unlock your device and you *do not* use the Panic Password, you cannot present a decoy account. The attacker will see your real messages. (LANMess wipes, it does not provide a fake identity).
- **Traffic Analysis:** While message contents are encrypted, the frame structure (sender name, counters, packet sizes, timing) remains visible to a passive observer. Use Tailscale, WireGuard, or a VPN to hide this metadata.
- **Compromise of a Peer's Device:** If your contact's device is compromised, the attacker gets access to the plaintext of every message you sent to them. End-to-end encryption cannot protect data once it is decrypted on the recipient's screen.
- **First-Contact MITM (Without Safety Numbers):** The initial add process relies on TOFU (Trust On First Use). A sophisticated attacker who intercepts the very first handshake *and* knows the 8-digit code could theoretically perform a MITM. You must press `V` and compare Safety Numbers out-of-band to close this gap.
- **No Independent Audit:** LANMess has not yet undergone a formal third-party security audit. While the primitives (AES, Ed25519, X25519, Argon2id) are industry standard, the implementation has not been verified by external experts.

## Scope

Discovery uses UDP broadcast and only travels within a single broadcast domain. To add peers across routed networks (like Tailscale), use the add-by-IP flow. This bypasses discovery and sends the signed handshake directly to the target address. TLS is not used on the wire in either mode, so metadata is not hidden.

## Roadmap to v2.0

- **Noise or TLS on the Wire:** Wrap the TCP transport in Noise IK or TLS 1.3 to hide frame structure and metadata from network observers.
- **Double Ratchet:** Upgrade the current symmetric hash ratchet to a full Double Ratchet (Signal spec) to provide Post-Compromise Security (self-healing after a key leak).
- **Signed Discovery Beacons:** Cryptographically sign the UDP beacons to prevent rogue peers from spamming the discovery list.
- **Duress / Decoy Account:** Upgrade the Panic Password from a "wipe" function to a "decoy" function, opening a plausible-looking empty vault instead of destroying the real one.
- **Signed Release Tags:** Sign Git commits and PyPI releases to guarantee the software hasn't been tampered with.
- **Independent Security Audit:** Commission a third-party review of the cryptographic implementation and threat model.