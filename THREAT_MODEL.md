# Threat Model

## Defended

- Passive LAN observer: message content and control payloads are encrypted.
- Active LAN attacker without group code or static keys: every frame is signed.
- Replay of captured messages: monotonic counters and one-way chain ratchet reject them.
- Beacon brute-force: `code_tag` is HMACed with a lookup key derived from the group code.
- First-contact MITM who knows the group code: challenge-response plus Ed25519 on every field.
- Stolen database file: master is random per device, recoverable only via Argon2id(PIN).
- Compromised static key after session end: session chains were ephemeral and forward-ratcheted.
- Message-length inference: 256-byte padding.
- Database row tampering: AES-GCM AAD per row.
- Audit log tampering: HMAC-chained entries detect any modification.
- Connection floods and slow-loris: rate limits, connection semaphore, frame caps.

## Not defended

- Rooted or unlocked device while logged in (in-memory keys readable by same UID).
- Coerced PIN disclosure (no duress mode).
- Traffic analysis of timing and packet volume on the wire (use Tailscale or a VPN).
- Compromise of a peer's device (their copy of your messages is exposed).
- First-contact MITM without out-of-band safety-number verification.
- Key rotation and revocation (no protocol for replacing a peer's key on a live identity).
- No independent audit has been performed.

## Roadmap to v2.0

- Noise or TLS on the wire to hide frame structure.
- Double Ratchet (Signal spec + test vectors) for post-compromise security.
- Signed discovery beacons with TOFU pinning per peer name.
- Session idle timeout.
- Signed release tags and pinned dependency hashes.
- Independent security audit.