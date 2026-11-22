# Threat Model

This document specifies what LANMess defends against, what it explicitly does not defend against, the assumptions it makes, and the residual risk that remains after the design as implemented.

It is intended to be read alongside `README.md`. Where the README summarizes, this document is the source of truth.

## Table of Contents

- Scope
- Assumptions
- Adversary Capabilities
- Defended Against
- Not Defended Against
- Residual Risk
- Cryptographic Choices
- Operational Security Notes

## Scope

LANMess is a peer-to-peer end-to-end encrypted messenger. Its security properties are defined only for:

- Two or more peers running the same version of LANMess.
- A network on which peers can reach each other directly (same broadcast domain, or a routed overlay such as Tailscale, WireGuard, or ZeroTier).
- A device whose operating system is not compromised at the time the app is running.

If any of these preconditions fails, the guarantees in this document do not apply.

## Assumptions

The following assumptions are made by the design:

1. The Ed25519 and X25519 primitives are secure. The `cryptography` library is a well-maintained binding to OpenSSL or libsodium. Failures at this layer are outside the scope of LANMess.

2. AES-256-GCM is secure. The implementation delegates to the same library.

3. Argon2id is secure. Provided by `argon2-cffi`. The parameters (t=3, m=64 MiB, p=4) are conservative for a PIN KDF.

4. The PIN is not trivially guessable. LANMess enforces a minimum length of 12 characters and requires at least three of four character classes, plus at least six distinct characters. This is a floor, not a ceiling.

5. The group code is not trivially guessable. Minimum length 12 characters. Peers sharing a group code are assumed to trust each other, since the code is what gates discovery and add-by-code.

6. The operating system provides isolation between processes. A compromised OS, a rogue root process, or a malicious kernel module is out of scope.

7. The device is not physically accessible to the adversary while the app is unlocked. Physical access while the app is running grants the adversary access to in-memory keys.

8. The system clock is roughly correct. Timestamps are checked against a 60-second replay window. A system clock that is hours or days off will cause valid frames to be rejected.

## Adversary Capabilities

The threat model considers the following classes of adversary:

### A1: Passive network observer

Can observe all traffic on the local network or overlay, including UDP beacons and TCP frames. Cannot modify, inject, or drop traffic.

### A2: Active network attacker

Can inject, modify, drop, delay, or replay any frame. Cannot break cryptographic primitives. Can perform a man-in-the-middle attack on the first-contact handshake if in the path at that moment.

### A3: Database thief

Has obtained the encrypted SQLite file (`lanmess.db` and optionally the `-wal` and `-shm` files). Does not have the PIN, does not have the master key, does not have access to the running device.

### A4: Contact impersonator

Can generate their own keys, has access to the group code, is on the same network, and is attempting to add the victim as a contact while pretending to be a known peer.

### A5: Brute-forcer

Has obtained the encrypted database and is attempting to guess the PIN or the panic password by trying candidate passwords offline, or is attempting to brute-force an add code by sending repeated `ADD_REQUEST` frames online.

### A6: Coercer

Has physical control of the device and is forcing the user to unlock the app. Motivated to see the real conversation history.

### A7: Unwanted peer

A known peer that the user no longer wants to hear from. Sends messages, presence, typing, chat requests, or repeated add requests.

## Defended Against

### Against A1: Passive observer

- **Message confidentiality.** All message bodies are encrypted with AES-256-GCM under per-session ratcheted keys. A passive observer sees only ciphertext.
- **Control frame confidentiality.** Add requests, chat start and accept, clear requests, presence, typing, and rotate frames are sent in cleartext JSON but contain no plaintext secrets: TOTP proofs are HMACs, and the signatures authenticate the frames.
- **Length hiding.** Message bodies are padded to 256-byte boundaries before encryption, so a passive observer cannot infer plaintext length from ciphertext length.
- **Identity confidentiality.** The long-term Ed25519 key is transmitted during discovery and the add handshake, but the private key never leaves the device.

### Against A2: Active network attacker

- **Frame authentication.** Every control frame is signed with Ed25519. A frame that has been modified, injected, or replayed will fail signature verification and be rejected.
- **Message authentication.** Chat messages are signed over the sender name, counter, nonce, ciphertext, and reply and reaction targets. An attacker cannot forge, mutate, replay, reorder, or reattribute a message without breaking Ed25519.
- **Replay protection.** The receiver tracks `recv_counter` and rejects any message with `counter <= recv_counter`. The sender advances its chain and counter before the network send, so a crash mid-send cannot cause key reuse.
- **Session integrity.** Session chains are derived from the X25519 shared secret and both ephemeral public keys, so an attacker who tampers with the handshake causes the derived chains to differ on the two sides, and all subsequent messages fail to decrypt.
- **First-contact man-in-the-middle (with TOTP).** The add handshake requires a proof that is HMACed under the current 8-digit TOTP code. An attacker who does not know the code cannot produce a valid `ADD_REQUEST` or `ADD_ACCEPT` even if they intercept the handshake.

### Against A3: Database thief

- **At-rest confidentiality.** The entire database is encrypted under a random per-device master key. The master key is stored in the vault table wrapped with Argon2id(PIN). An attacker with the `.db` file cannot read identity, contacts, messages, audit entries, or the blocklist without the PIN.
- **Row binding.** Every encrypted row is bound to its context through AAD: `contact:<name_hash>` for contacts, `message:<contact_id>:<row_id>` for messages, `audit:<prev_hmac>` for audit entries, `blocked:<name_hash>` for blocked entries, `pending_rotate:<name_hash>` for queued rotations. Ciphertexts cannot be swapped between rows.
- **No plaintext metadata.** The meta table contains only schema version numbers and one-time migration flags. Contact names are hashed with the lookup key. Messages carry no plaintext sender, recipient, or timestamp fields outside the encrypted blob.
- **Panic password does not leak the PIN or its hash.** The panic password is stored as `v10:` + Base64 of `nonce || AES-256-GCM(Argon2id(pin, salt), 32-byte marker)`, authenticated under AAD `b"lanmess-panic-v1"`. No raw Argon2id output is written to disk. An attacker with the database cannot verify a candidate panic PIN without running Argon2id and passing the GCM authentication tag, then matching the constant marker via `compare_digest`. This is the same cost as brute-forcing the vault PIN.
- **Legacy panic format is compatible but weaker.** Pre-v1.1.13 panic PINs are stored as a plain Argon2id hex hash. Verification still runs Argon2id, so offline guessing is expensive, but the stored value is a hash rather than a ciphertext and could be reused as a rainbow-table input if the salt were reused (it is not, since each set generates a fresh 16-byte salt). Re-setting the panic password upgrades the storage format to v10 automatically.

### Against A4: Contact impersonator

- **Key pinning.** Once a contact's Ed25519 key is stored, any add request or chat frame with a different key is rejected. The user must explicitly delete and re-add the contact to accept a new key.
- **TOTP gating.** An impersonator who does not know the current 8-digit code cannot produce a valid proof even if they know the group code and are on the same network.
- **Safety numbers.** Users are prompted to compare a 60-digit safety number out-of-band. Two peers who compare safety numbers are protected against a first-contact man-in-the-middle, even one that knows the TOTP code.

### Against A5: Brute-forcer

- **Argon2id KDF.** The PIN and the panic PIN are stretched with Argon2id (t=3, m=64 MiB, p=4), which makes offline brute-force attacks expensive.
- **Exponential lockout.** Failed PIN attempts trigger a 30-second lockout after five failures, five minutes after ten, one hour after twenty, and twenty-four hours after fifty. Attempt counts and lockout deadlines are stored in the security table and survive restart.
- **Panic PIN is encrypted, not hashed.** Because the stored panic value is AES-GCM ciphertext under the Argon2id-derived key, verifying a candidate requires deriving the key, passing the 128-bit GCM authentication tag, and matching the 32-byte constant marker. There is no shortcut that skips the KDF.
- **Per-IP and per-name rate limit on add requests.** The `ADD_REQUEST` handler enforces `ADD_RATE_LIMIT_SECONDS` on both the source IP and the claimed `from_name`. An attacker rotating source addresses cannot bypass the per-name limit, and an attacker reusing a single source address cannot bypass the per-IP limit.

### Against A6: Coercer

- **Panic password.** Entering the panic PIN at the unlock screen zeroes the master key in memory, wipes the database, deletes the SQLite WAL, SHM, and journal files, and exits.
- **Deniable panic PIN.** Because the panic PIN hash and the vault PIN hash both use Argon2id under per-database salts, and because the stored panic value is opaque ciphertext, a coercer examining the database cannot tell whether a panic PIN has been configured by inspection alone.

### Against A7: Unwanted peer

- **Persistent block.** A blocked peer is refused service in `_verify_peer_sig_no_touch`, which every handler uses, and additionally in `_handle_add_request`, `_handle_add_accept`, `_handle_rotate`, `_handle_message`, `start_chat`, `send_chat_message`, and `request_clear_all`. The block survives contact deletion because it is stored in a separate `blocked` table keyed by the name hash.
- **No re-add.** `_process_add_response` refuses to re-add a blocked contact. The only way to allow them back is `/unblock`.
- **Session termination.** Blocking a contact with an active chat stops the chat before the block is applied, so chains and counters are cleared, and queued outbox messages are dropped on the next outbox loop.
- **Outbox is drained.** The outbox loop drops any queued messages for a contact that becomes blocked or unverified.
- **Audit.** Both `BLOCKED_LOCAL` and `UNBLOCKED_LOCAL` are written to the audit chain.

## Not Defended Against

The following threats are explicitly outside the scope of the design:

- **Rooted or unlocked device while the app is running.** An attacker with physical access to the device while the app is unlocked can read in-memory keys and plaintext messages.
- **Traffic analysis and metadata correlation.** An observer can see when peers are online, how often they communicate, the size of their messages (bucketed to 256 bytes), and the timing of their traffic. LANMess does not attempt to hide this.
- **Compromise of a peer's device after decryption.** End-to-end encryption protects data in transit. Once a message is decrypted on the recipient's screen, it is plaintext on the recipient's device. If that device is compromised, the attacker sees the message.
- **Nation-state adversaries with sustained, targeted access.** The threat model assumes a competent, motivated attacker, not an adversary with pervasive network access, supply-chain control, or endpoint exploitation capability.
- **Supply-chain compromise of the Python runtime or the cryptography library.** If the Python interpreter, the `cryptography` library, or the `argon2-cffi` library is compromised, the guarantees in this document are void.
- **Side-channel attacks on the CPU or memory.** Spectre-class attacks, power analysis, and electromagnetic emanation are out of scope.
- **First-contact man-in-the-middle without safety-number verification.** If an attacker is in the path during the very first handshake and knows the 8-digit TOTP code, they can perform a man-in-the-middle attack. The mitigation is to compare safety numbers out-of-band.
- **Independent audit.** LANMess has not undergone a formal third-party security audit. The primitives are standard; the implementation has not been independently reviewed.
- **Post-compromise security.** The symmetric hash ratchet provides forward secrecy within a session, but not post-compromise security. If a device is compromised and a session is ongoing, the attacker can read future messages in that session.
- **Denial of service via resource exhaustion.** An attacker who can flood the TCP port or the UDP discovery port can degrade service. Per-IP rate limits, per-name rate limits, and connection caps reduce but do not eliminate this risk.
- **Blocked peer exfiltrating past data.** Blocking prevents future communication. It does not un-send messages the peer already has, and it does not revoke keys the peer already knows.
- **Passive confirmation of a panic PIN from stored data.** An attacker with the database cannot test candidate panic PINs without running Argon2id, but once a candidate has been tested, the result is deterministic. That is inherent to any password verification scheme that does not require interaction with the device. Storing the panic PIN as ciphertext rather than a hash raises the cost of the attack but does not eliminate it.

## Residual Risk

After applying all mitigations, the following residual risk remains:

1. **First-contact man-in-the-middle without out-of-band verification.** A sophisticated attacker who intercepts the very first handshake and knows the TOTP code can man-in-the-middle the session. The only mitigation is manual safety-number comparison.

2. **Compromised peer device.** If a peer's device is compromised, the attacker sees all plaintext messages that peer has received.

3. **Weak user PIN.** Argon2id makes brute-forcing expensive, but a user who chooses a common password is still at risk. The minimum-strength check is a floor, not a guarantee.

4. **Traffic metadata.** An observer learns who is talking to whom, when, and how often. LANMess does not attempt to hide this.

5. **Clock skew.** If the system clock is more than 60 seconds off, valid frames will be rejected as stale. Users on systems without NTP may experience intermittent failures.

6. **Migration bugs.** The v1 to v10 migration path is exercised by the test suite, but a user with a heavily customised database could encounter an edge case that the tests do not cover. Back up `~/.lanmess/lanmess.db` before upgrading.

7. **Best-effort secure deletion.** SQLite overwrites deleted pages with `secure_delete=ON`, but the underlying storage may retain old data. Full-disk encryption is recommended.

8. **Block is local.** Blocking a peer refuses their frames on this device only. It does not notify them, does not propagate to other peers, and cannot prevent them from attempting to contact other devices on the same network.

9. **Panic PIN verification is still a KDF operation.** Storing the panic PIN as ciphertext under Argon2id prevents an attacker with the database from comparing hashes directly, but a candidate panic PIN can still be tested offline by running Argon2id. This is the same cost as guessing the vault PIN. There is no way around it without an additional factor or an online check against a remote authority, both of which LANMess does not have.

## Cryptographic Choices

Each primitive and parameter was chosen for a specific reason:

- **Ed25519 over RSA or ECDSA.** Smaller keys, faster verification, deterministic signatures, no need for a random nonce. The `cryptography` library provides a well-tested implementation.

- **X25519 over P-256 or P-384.** Constant-time by construction, simpler to implement correctly, no need for point validation.

- **AES-256-GCM over ChaCha20-Poly1305.** AES-GCM is hardware-accelerated on most modern CPUs via AES-NI. On platforms without AES-NI, ChaCha20-Poly1305 would be faster, but the AES-GCM implementation is still fast enough for a text messenger.

- **HKDF-SHA256 for session chains.** HKDF is the standard KDF for extracting and expanding key material. The salt is the concatenation of both ephemeral public keys in sorted order, so both peers derive the same chains without an extra round trip.

- **HMAC-SHA256 for the ratchet.** A one-way function with a well-understood security proof. The chain step and message key derivations use different labels to ensure domain separation.

- **Argon2id for PIN stretching.** Winner of the Password Hashing Competition. The `id` variant is resistant to both side-channel and GPU attacks. The parameters follow OWASP recommendations for interactive logins.

- **AES-GCM for the panic marker.** The panic password is verified by decrypting a fixed 32-byte marker under `key = Argon2id(panic_pin, salt)` with AAD `b"lanmess-panic-v1"` and comparing against the constant via `hmac.compare_digest`. This makes the stored value opaque ciphertext rather than a hash, so an attacker with the database file cannot perform hash-based attacks (rainbow tables, hash shucking, reuse of an identical hash across devices) even if two devices happen to have the same panic password. The GCM tag catches a wrong key, and the constant comparison catches format confusion.

- **PBKDF2-HMAC-SHA256 for the group code.** The group code is a shared secret used once at startup, not a password entered on every login. PBKDF2 with 600,000 iterations is sufficient and avoids a hard dependency on Argon2 for the group-key derivation path.

- **256-byte padding.** A multiple of the AES block size and a common bucket size. Short messages and long messages are indistinguishable up to the bucket boundary.

## Operational Security Notes

The following practices are recommended for users who rely on LANMess for sensitive communication:

1. **Back up `~/.lanmess/lanmess.db` before upgrading.** The migration path is tested, but a backup costs nothing and protects against edge cases.

2. **Compare safety numbers out-of-band.** After adding a contact, press `V` and compare the 60-digit safety number over a channel you already trust. This is the only defence against a first-contact man-in-the-middle.

3. **Use a strong PIN.** The minimum is 12 characters with three character classes. A diceware passphrase or a randomly generated password is better. Use `/changepin` if you need to rotate the PIN without changing the identity.

4. **Configure a panic password if you are at risk of coercion.** The panic password wipes the database; it does not open a decoy vault. If plausible deniability is required, understand that the coercer will see a reset app, not a fake conversation history. Choose a panic password that is different from the unlock PIN, since the two share no storage and nothing prevents them from being identical, but they should be treated as independent secrets.

5. **Re-set the panic password after upgrading from v1.1.12 or earlier.** Pre-v1.1.13 panic PINs are stored as a plain Argon2id hex hash, which is not the new encrypted format. Re-setting the panic password (via the menu, or by clearing and re-entering it) upgrades the storage format to v10 automatically. Verification continues to work for both formats.

6. **Enable auto-lock.** Set a timeout that fits how you use the app. The default is 15 minutes.

7. **Enable full-disk encryption.** The database is encrypted, but the WAL and SHM files, the swap file, and the filesystem journal may contain fragments of plaintext or key material. Full-disk encryption closes this gap.

8. **Keep the system clock accurate.** A clock that is more than 60 seconds off will cause valid frames to be rejected. Enable NTP.

9. **Do not run LANMess on a shared or untrusted device.** The master key lives in process memory while the app is unlocked. A root process on the same device can read it.

10. **Rotate keys if you suspect compromise.** The Rotate Keys menu action generates new Ed25519 and X25519 keys and broadcasts a signed `ROTATE` frame to every contact. The old keys are not escrowed; a contact who does not receive the rotate frame will be unable to communicate with you until they re-add you. Use `/rotations` to check pending deliveries after rotating.

11. **Block aggressively if you are being harassed.** `/block` refuses the peer's frames on this device and records the event in the audit chain. Because the block survives contact deletion, deleting a contact is no longer a way to accidentally let them back in.