import asyncio
import base64
import hashlib
import hmac
import os
import time

import lanmess_files.tui as _tui

from ..config import (
    ADD_RATE_LIMIT_MAX,
    ADD_RATE_LIMIT_SECONDS,
    MAX_CHAIN_GAP,
    MAX_MESSAGE_LEN,
    MSG_RATE_LIMIT_MAX,
    MSG_RATE_LIMIT_SECONDS,
    NOTIFY_BODY_MAX,
    PROBE_TIMEOUT,
)
from ..crypto import (
    aes_gcm_decrypt,
    chain_advance,
    chain_message_key,
    compute_totp,
    derive_session_chains,
    ed_public_from_bytes,
    ed_public_to_bytes,
    unpad_message,
    verify_bytes,
    x25519_private_from_bytes,
    x25519_public_from_bytes,
    x25519_public_to_bytes,
)
from ..notifications import notify
from .helpers import _now_ms


async def send_request(*args, **kwargs):
    return await _tui.send_request(*args, **kwargs)


class HandlersMixin:
    async def handle_incoming(self, msg):
        t = msg.get("type")
        try:
            if t == "ADD_REQUEST":
                return await self._handle_add_request(msg)
            if t == "ADD_ACCEPT":
                return await self._handle_add_accept(msg)
            if t == "ADD_REJECT":
                return await self._handle_add_reject(msg)
            if t == "ROTATE":
                return await self._handle_rotate(msg)
            if t == "CHAT_START":
                return await self._handle_chat_start(msg)
            if t == "CHAT_ACCEPT":
                return await self._handle_chat_accept(msg)
            if t == "CHAT_REJECT":
                return await self._handle_chat_reject(msg)
            if t == "CHAT_STOP":
                return await self._handle_chat_stop(msg)
            if t == "CLEAR_REQUEST":
                return await self._handle_clear_request(msg)
            if t == "CLEAR_ACCEPT":
                return await self._handle_clear_accept(msg)
            if t == "CLEAR_REJECT":
                return await self._handle_clear_reject(msg)
            if t == "MESSAGE":
                return await self._handle_message(msg)
            if t == "PRESENCE":
                return await self._handle_presence(msg)
            if t == "TYPING":
                return await self._handle_typing(msg)
        except Exception:
            return {"type": "ERROR", "reason": "handler_error"}
        return {"type": "ERROR", "reason": "unknown"}

    async def _handle_add_request(self, msg):
        peer_ip = msg.get("_peer_ip")
        now = time.time()
        if peer_ip:
            last = self._add_attempts.get(peer_ip, 0)
            if now - last < ADD_RATE_LIMIT_SECONDS:
                return {
                    "type": "ADD_REJECT",
                    "reason": "rate_limited",
                }
            self._add_attempts[peer_ip] = now
            self._prune_dict(
                self._add_attempts, ADD_RATE_LIMIT_MAX
            )
        ts = msg.get("timestamp")
        if not self._valid_timestamp(ts):
            return {
                "type": "ADD_REJECT",
                "reason": "stale",
            }
        from_name = msg.get("from_name")
        from_ed = msg.get("from_ed_pub")
        from_x = msg.get("from_x25519_pub")
        from_port = msg.get("from_port")
        challenge_b64 = msg.get("challenge")
        proof_hex = msg.get("proof")
        if not self._valid_name(from_name):
            return {
                "type": "ADD_REJECT",
                "reason": "missing_name",
            }
        if from_name == self.user_name:
            return {
                "type": "ADD_REJECT",
                "reason": "self",
            }
        if not self._valid_hex(from_ed, 32):
            return {
                "type": "ADD_REJECT",
                "reason": "missing_ed_key",
            }
        if not self._valid_hex(from_x, 32):
            return {
                "type": "ADD_REJECT",
                "reason": "missing_x_key",
            }
        if not isinstance(from_port, int) or not (
            1 <= from_port <= 65535
        ):
            from_port = None
        try:
            challenge = base64.b64decode(challenge_b64)
        except Exception:
            return {
                "type": "ADD_REJECT",
                "reason": "bad_challenge",
            }
        if len(challenge) != 32:
            return {
                "type": "ADD_REJECT",
                "reason": "bad_challenge",
            }
        try:
            given_proof = bytes.fromhex(proof_hex)
        except (TypeError, ValueError):
            return {
                "type": "ADD_REJECT",
                "reason": "bad_proof",
            }
        if len(given_proof) != 32:
            return {
                "type": "ADD_REJECT",
                "reason": "bad_proof",
            }
        proof_ok = False
        for offset in (0, -1):
            code = compute_totp(
                self.totp_secret, offset
            )
            expected = hmac.new(
                code.encode("utf-8"),
                b"REQ"
                + from_name.encode("utf-8")
                + challenge,
                hashlib.sha256,
            ).digest()
            if hmac.compare_digest(
                expected, given_proof
            ):
                proof_ok = True
                break
        if not proof_ok:
            self._audit(
                "ADD_INVALID_CODE",
                {"from": from_name},
            )
            return {
                "type": "ADD_REJECT",
                "reason": "invalid_code",
            }
        try:
            from_pk = ed_public_from_bytes(
                bytes.fromhex(from_ed)
            )
        except Exception:
            return {
                "type": "ADD_REJECT",
                "reason": "bad_key",
            }
        if not self._check_signed(msg, from_pk):
            self._audit(
                "ADD_BAD_SIGNATURE",
                {"from": from_name},
            )
            return {
                "type": "ADD_REJECT",
                "reason": "bad_signature",
            }
        self._touch_heard(from_name)
        existing = self.db.get_contact(from_name)
        if existing:
            if existing.get("blocked"):
                return {
                    "type": "ADD_REJECT",
                    "reason": "blocked",
                }
            if existing["ed_public_hex"] != from_ed:
                return {
                    "type": "ADD_REJECT",
                    "reason": "key_mismatch",
                }
        peer = self.discovery.find_by_name(from_name)
        ip = peer["ip"] if peer else peer_ip
        port = peer["tcp_port"] if peer else from_port
        self.db.upsert_contact(
            name=from_name,
            ip=ip,
            port=port,
            ed_public_hex=from_ed,
            x25519_public_hex=from_x,
        )
        self._audit(
            "ADD_REQUEST_RECEIVED", {"from": from_name}
        )
        resp_challenge = os.urandom(32)
        resp_code = compute_totp(self.totp_secret, 0)
        resp_proof = hmac.new(
            resp_code.encode("utf-8"),
            b"ACC"
            + self.user_name.encode("utf-8")
            + resp_challenge,
            hashlib.sha256,
        ).digest()
        resp_fields = {
            "to_name": self.user_name,
            "to_ed_pub": ed_public_to_bytes(
                self.ed_public
            ).hex(),
            "to_x25519_pub": x25519_public_to_bytes(
                self.x25519_public
            ).hex(),
            "challenge": base64.b64encode(
                resp_challenge
            ).decode("ascii"),
            "proof": resp_proof.hex(),
            "timestamp": _now_ms(),
        }
        if existing is None:
            self.db.set_contact_state(
                from_name, pending=2
            )
            self._refresh_main()
            self.notify(
                f"{from_name} wants to add you. "
                "Press Y to accept, X to reject."
            )
            return self._signed(
                {"type": "ADD_PENDING", **resp_fields}
            )
        if existing.get("pending") == 0:
            return self._signed(
                {"type": "ADD_ACCEPT", **resp_fields}
            )
        if existing.get("pending") == 1:
            self.db.set_contact_state(
                from_name, pending=0
            )
            self._refresh_main()
            self.notify(
                f"Mutual add completed with {from_name}."
            )
            self._audit(
                "ADD_MUTUAL", {"contact": from_name}
            )
            return self._signed(
                {"type": "ADD_ACCEPT", **resp_fields}
            )
        self._refresh_main()
        return self._signed(
            {"type": "ADD_PENDING", **resp_fields}
        )

    async def _handle_add_accept(self, msg):
        from_name = msg.get("from_name")
        if not self._valid_name(from_name):
            return {"type": "OK"}
        contact = self.db.get_contact(from_name)
        if not contact:
            return {"type": "OK"}
        from_ed = msg.get("from_ed_pub")
        from_x = msg.get("from_x25519_pub")
        ts = msg.get("timestamp")
        if not self._valid_hex(from_ed, 32):
            return {"type": "OK"}
        if not self._valid_hex(from_x, 32):
            return {"type": "OK"}
        if not self._valid_timestamp(ts):
            return {"type": "OK"}
        if contact["ed_public_hex"] != from_ed:
            self.notify(
                f"Rejected add-accept from {from_name}: "
                "key mismatch.",
                severity="error",
            )
            return {"type": "OK"}
        try:
            peer_pk = ed_public_from_bytes(
                bytes.fromhex(from_ed)
            )
        except Exception:
            return {"type": "OK"}
        if not self._check_signed(msg, peer_pk):
            return {"type": "OK"}
        self._touch_heard(from_name)
        self._apply_peer_ip(msg, from_name)
        if contact.get("pending") in (1, 2):
            self.db.set_contact_state(
                from_name,
                pending=0,
                x25519_public_hex=from_x,
            )
            self._refresh_main()
            self.notify(
                f"{from_name} accepted your add request."
            )
            self._audit(
                "ADD_ACCEPTED", {"contact": from_name}
            )
        return {"type": "OK"}

    async def _handle_add_reject(self, msg):
        from_name = msg.get("from_name")
        if not self._valid_name(from_name):
            return {"type": "OK"}
        contact = self.db.get_contact(from_name)
        if not contact:
            return {"type": "OK"}
        try:
            peer_pk = ed_public_from_bytes(
                bytes.fromhex(contact["ed_public_hex"])
            )
        except Exception:
            return {"type": "OK"}
        if not self._check_signed(msg, peer_pk):
            return {"type": "OK"}
        ts = msg.get("timestamp")
        if not self._valid_timestamp(ts):
            return {"type": "OK"}
        self._touch_heard(from_name)
        self._apply_peer_ip(msg, from_name)
        if contact.get("pending") == 1:
            self.db.delete_contact(from_name)
            self._refresh_main()
            self._refresh_visible_messages()
            self.notify(
                f"{from_name} rejected your add request."
            )
            self._audit(
                "ADD_REJECTED", {"contact": from_name}
            )
        return {"type": "OK"}

    async def _handle_rotate(self, msg):
        from_name = msg.get("from_name")
        if not self._valid_name(from_name):
            return {"type": "OK"}
        contact = self.db.get_contact(from_name)
        if not contact:
            return {"type": "OK"}
        try:
            old_pk = ed_public_from_bytes(
                bytes.fromhex(contact["ed_public_hex"])
            )
        except Exception:
            return {"type": "OK"}
        if not self._check_signed(msg, old_pk):
            return {"type": "OK"}
        ts = msg.get("timestamp")
        if not self._valid_timestamp(ts):
            return {"type": "OK"}

        new_ed = msg.get("new_ed_pub")
        new_x = msg.get("new_x25519_pub")
        if not self._valid_hex(new_ed, 32) or not self._valid_hex(
            new_x, 32
        ):
            return {"type": "OK"}

        self.db.update_contact_keys(from_name, new_ed, new_x)
        self._touch_heard(from_name)
        self.notify(
            f"{from_name} rotated their keys. "
            "Session preserved."
        )
        self._audit(
            "KEY_ROTATED_PEER", {"contact": from_name}
        )
        self._refresh_main()
        self._refresh_visible_messages()
        return {"type": "OK"}

    async def _verify_peer_sig_no_touch(self, msg):
        from_name = msg.get("from_name")
        if not self._valid_name(from_name):
            return None
        contact = self.db.get_contact(from_name)
        if not contact:
            return None
        try:
            pk = ed_public_from_bytes(
                bytes.fromhex(contact["ed_public_hex"])
            )
        except Exception:
            return None
        if not self._check_signed(msg, pk):
            return None
        ts = msg.get("timestamp")
        if not self._valid_timestamp(ts):
            return None
        self._apply_peer_ip(msg, from_name)
        contact = self.db.get_contact(from_name)
        return contact

    async def _verify_peer_sig(self, msg):
        contact = await self._verify_peer_sig_no_touch(msg)
        if contact:
            self._touch_heard(contact["name"])
        return contact

    async def _handle_chat_start(self, msg):
        contact = await self._verify_peer_sig(msg)
        if not contact:
            return {
                "type": "CHAT_REJECT",
                "reason": "invalid",
            }
        if contact.get("blocked"):
            return {
                "type": "CHAT_REJECT",
                "reason": "blocked",
            }
        if contact.get("pending") != 0:
            return {
                "type": "CHAT_REJECT",
                "reason": "pending",
            }
        if (
            self.db.get_verified_only()
            and not contact.get("verified")
        ):
            return {
                "type": "CHAT_REJECT",
                "reason": "unverified",
            }
        try:
            peer_eph_raw = base64.b64decode(
                msg["eph_pub"]
            )
        except Exception:
            return {
                "type": "CHAT_REJECT",
                "reason": "bad_eph",
            }
        if len(peer_eph_raw) != 32:
            return {
                "type": "CHAT_REJECT",
                "reason": "bad_eph",
            }
        if contact.get("chat_started"):
            return {"type": "CHAT_PENDING"}
        self.db.set_contact_state(
            contact["name"],
            incoming_request=1,
            session_peer_eph_pub_hex=peer_eph_raw.hex(),
        )
        self._refresh_main()
        self.notify(
            f"{contact['name']} wants to chat. "
            "Press Y to accept."
        )
        self._audit(
            "CHAT_START_RECEIVED",
            {"contact": contact["name"]},
        )
        return {"type": "CHAT_PENDING"}

    async def _handle_chat_accept(self, msg):
        contact = await self._verify_peer_sig(msg)
        if not contact:
            return {"type": "OK"}
        try:
            peer_eph_raw = base64.b64decode(
                msg["eph_pub"]
            )
        except Exception:
            return {"type": "OK"}
        if len(peer_eph_raw) != 32:
            return {"type": "OK"}
        local_sk_hex = contact.get(
            "session_local_eph_sk_hex", ""
        )
        if not local_sk_hex:
            return {"type": "OK"}
        try:
            local_sk = x25519_private_from_bytes(
                bytes.fromhex(local_sk_hex)
            )
        except Exception:
            return {"type": "OK"}
        try:
            peer_eph_pub = x25519_public_from_bytes(
                peer_eph_raw
            )
            shared = local_sk.exchange(peer_eph_pub)
        except Exception:
            return {"type": "OK"}
        local_eph_pub = x25519_public_to_bytes(
            local_sk.public_key()
        )
        chains = derive_session_chains(
            shared, local_eph_pub, peer_eph_raw
        )
        send_chain = chains[0:32]
        recv_chain = chains[32:64]
        self.db.set_contact_state(
            contact["name"],
            chat_started=1,
            incoming_request=0,
            session_established=1,
            send_chain_key_hex=send_chain.hex(),
            recv_chain_key_hex=recv_chain.hex(),
            send_counter=0,
            recv_counter=0,
            session_local_eph_sk_hex="",
            session_peer_eph_pub_hex="",
        )
        self._touch_activity(contact["name"])
        self._refresh_main()
        self.notify(
            f"Chat started with {contact['name']}."
        )
        self._audit(
            "CHAT_START_ACCEPTED",
            {"contact": contact["name"]},
        )
        asyncio.create_task(
            self._send_presence_now(contact["name"])
        )
        return {"type": "OK"}

    async def _handle_chat_reject(self, msg):
        contact = await self._verify_peer_sig(msg)
        if contact:
            self.notify(
                f"{contact['name']} rejected your chat "
                "request."
            )
        return {"type": "OK"}

    async def _handle_chat_stop(self, msg):
        contact = await self._verify_peer_sig(msg)
        if not contact:
            return {"type": "OK"}
        self.db.set_contact_state(
            contact["name"],
            chat_started=0,
            incoming_request=0,
            session_established=0,
            send_chain_key_hex="",
            recv_chain_key_hex="",
            send_counter=0,
            recv_counter=0,
            session_local_eph_sk_hex="",
            session_peer_eph_pub_hex="",
        )
        name = contact["name"]
        self._last_activity.pop(name, None)
        self._last_heard.pop(name, None)
        self._peer_offline.pop(name, None)
        self._peer_typing.pop(name, None)
        self._presence_success.pop(name, None)
        self._presence_fail.pop(name, None)
        self._last_typing_sent.pop(name, None)
        self._refresh_main()
        self._refresh_visible_messages()
        self.notify(
            f"{name} stopped the chat."
        )
        self._audit(
            "CHAT_STOP_RECEIVED",
            {"contact": name},
        )
        return {"type": "OK"}

    async def _handle_clear_request(self, msg):
        contact = await self._verify_peer_sig(msg)
        if not contact:
            return {
                "type": "CLEAR_REJECT",
                "reason": "invalid",
            }
        if contact.get("blocked"):
            return {
                "type": "CLEAR_REJECT",
                "reason": "blocked",
            }
        if contact.get("pending") != 0:
            return {
                "type": "CLEAR_REJECT",
                "reason": "pending",
            }
        self.db.set_contact_state(
            contact["name"], clear_pending=1
        )
        self._refresh_main()
        self._refresh_visible_messages()
        self.notify(
            f"{contact['name']} wants to clear the "
            "conversation. Press Y to accept, X to "
            "reject."
        )
        self._audit(
            "CLEAR_REQUEST_RECEIVED",
            {"contact": contact["name"]},
        )
        return {"type": "CLEAR_PENDING"}

    async def _handle_clear_accept(self, msg):
        contact = await self._verify_peer_sig(msg)
        if not contact:
            return {"type": "OK"}
        self.db.clear_messages(contact["name"])
        self.db.set_contact_state(
            contact["name"], clear_pending=0
        )
        self._refresh_main()
        self._refresh_visible_messages()
        self.notify(
            f"{contact['name']} accepted. "
            "Conversation cleared."
        )
        self._audit(
            "CLEAR_ACCEPTED",
            {"contact": contact["name"]},
        )
        return {"type": "OK"}

    async def _handle_clear_reject(self, msg):
        contact = await self._verify_peer_sig(msg)
        if not contact:
            return {"type": "OK"}
        self.db.set_contact_state(
            contact["name"], clear_pending=0
        )
        self.notify(
            f"{contact['name']} declined the clear "
            "request."
        )
        self._audit(
            "CLEAR_REJECTED",
            {"contact": contact["name"]},
        )
        return {"type": "OK"}

    async def _handle_presence(self, msg):
        contact = await self._verify_peer_sig_no_touch(msg)
        if not contact:
            return {"type": "OK"}
        name = contact["name"]
        status = msg.get("status", "online")
        if status == "offline":
            self._mark_offline(name)
            self._refresh_main()
            return {"type": "OK"}
        self._touch_heard(name)
        self._refresh_main()

        if name in self._pending_rotates:
            payload = self._pending_rotates[name]
            try:
                ip, port = self._resolve_peer_address(contact)
                if ip and port:
                    resp = await send_request(
                        ip, port, payload,
                        timeout=PROBE_TIMEOUT
                    )
                    if resp:
                        del self._pending_rotates[name]
            except Exception:
                pass

        if not self.db.get_presence_enabled():
            return {"type": "ERROR", "reason": "presence_off"}
        return {"type": "OK"}

    async def _handle_typing(self, msg):
        contact = await self._verify_peer_sig(msg)
        if not contact:
            return {"type": "OK"}
        self._peer_typing[contact["name"]] = time.time()
        return {"type": "OK"}

    async def _handle_message(self, msg):
        peer_ip = msg.get("_peer_ip")
        now = time.time()
        if peer_ip:
            last = self._msg_attempts.get(peer_ip, 0)
            if now - last < MSG_RATE_LIMIT_SECONDS:
                return {"type": "ERROR", "reason": "rate_limited"}
            self._msg_attempts[peer_ip] = now
            self._prune_dict(
                self._msg_attempts, MSG_RATE_LIMIT_MAX
            )
        from_name = msg.get("from_name")
        if not self._valid_name(from_name):
            return {"type": "ERROR", "reason": "bad_name"}
        contact = self.db.get_contact(from_name)
        if not contact:
            return {"type": "ERROR", "reason": "unknown_contact"}
        if contact.get("blocked"):
            return {"type": "ERROR", "reason": "blocked"}
        if not contact.get("chat_started"):
            return {"type": "ERROR", "reason": "no_chat"}
        if contact.get("pending") != 0:
            return {"type": "ERROR", "reason": "pending"}
        if not contact.get("session_established"):
            return {"type": "ERROR", "reason": "no_session"}
        if (
            self.db.get_verified_only()
            and not contact.get("verified")
        ):
            return {"type": "ERROR", "reason": "unverified"}
        counter = msg.get("counter")
        if (
            not isinstance(counter, int)
            or counter <= 0
            or counter > 2**63 - 1
        ):
            return {"type": "ERROR", "reason": "bad_counter"}
        try:
            nonce = base64.b64decode(msg["nonce"])
            ct = base64.b64decode(msg["ciphertext"])
            sig = base64.b64decode(msg["signature"])
        except Exception:
            return {"type": "ERROR", "reason": "bad_frame"}
        if len(nonce) != 12 or len(ct) < 16 or len(sig) != 64:
            return {"type": "ERROR", "reason": "bad_frame"}
        try:
            reply_to = int(msg.get("reply_to", 0) or 0)
        except (TypeError, ValueError):
            reply_to = 0
        try:
            react_to = int(msg.get("react_to", 0) or 0)
        except (TypeError, ValueError):
            react_to = 0
        if reply_to < 0 or react_to < 0:
            return {"type": "ERROR", "reason": "bad_frame"}
        signed_data = (
            from_name.encode("utf-8")
            + counter.to_bytes(8, "big")
            + nonce
            + ct
            + reply_to.to_bytes(8, "big")
            + react_to.to_bytes(8, "big")
        )
        try:
            ed_pk = ed_public_from_bytes(
                bytes.fromhex(contact["ed_public_hex"])
            )
        except Exception:
            return {"type": "ERROR", "reason": "bad_key"}
        if not verify_bytes(ed_pk, sig, signed_data):
            self.notify(
                f"Signature failure from {from_name}.",
                severity="error",
            )
            self._audit(
                "SIG_FAILURE", {"contact": from_name}
            )
            return {"type": "ERROR", "reason": "sig_fail"}
        self._touch_heard(from_name)
        recv_counter = contact.get("recv_counter", 0)
        if counter <= recv_counter:
            return {"type": "ERROR", "reason": "replay"}
        recv_chain_hex = contact.get(
            "recv_chain_key_hex", ""
        )
        if not recv_chain_hex:
            return {"type": "ERROR", "reason": "no_chain"}
        try:
            recv_chain = bytes.fromhex(recv_chain_hex)
        except ValueError:
            return {"type": "ERROR", "reason": "bad_chain"}
        gap = counter - recv_counter - 1
        if gap > MAX_CHAIN_GAP:
            return {"type": "ERROR", "reason": "gap_too_big"}
        for _ in range(gap):
            recv_chain = chain_advance(recv_chain)
        msg_key = chain_message_key(recv_chain)
        aad = (
            f"{from_name}:{counter}".encode("utf-8")
        )
        try:
            padded = aes_gcm_decrypt(
                msg_key, nonce, ct, aad
            )
        except Exception:
            self.notify(
                f"Decryption failure from {from_name}.",
                severity="error",
            )
            self._audit(
                "DEC_FAILURE", {"contact": from_name}
            )
            return {"type": "ERROR", "reason": "dec_fail"}
        try:
            text = unpad_message(padded).decode(
                "utf-8", errors="replace"
            )
        except Exception:
            return {"type": "ERROR", "reason": "bad_pad"}
        if len(text) > MAX_MESSAGE_LEN:
            text = text[:MAX_MESSAGE_LEN]
        new_chain = chain_advance(recv_chain)
        self.db.add_message(
            from_name,
            "in",
            text,
            reply_to=reply_to,
            react_to=react_to,
        )
        self.db.set_contact_state(
            from_name,
            recv_chain_key_hex=new_chain.hex(),
            recv_counter=counter,
        )
        if peer_ip and peer_ip != contact.get("ip"):
            if not contact.get("pinned"):
                self.db.set_contact_state(
                    from_name, ip=peer_ip
                )
        if not self._is_currently_viewing(from_name):
            self.db.increment_unread(from_name)
        self._touch_activity(from_name)
        try:
            enabled = self.db.get_notifications_enabled()
            if react_to:
                notif_body = (
                    f"reacted to #{react_to}: {text}"
                )
            elif reply_to:
                notif_body = (
                    f"re #{reply_to}: {text[:NOTIFY_BODY_MAX]}"
                )
            else:
                notif_body = text[:NOTIFY_BODY_MAX]
            asyncio.create_task(
                asyncio.to_thread(
                    notify,
                    from_name,
                    notif_body,
                    enabled=enabled,
                )
            )
        except Exception:
            pass
        asyncio.create_task(
            self._deferred_refresh(from_name)
        )
        return {"type": "OK"}

    async def _deferred_refresh(self, contact_name):
        try:
            screen = self._get_main_screen()
            if screen is None:
                return
            screen.refresh_contacts()
            if screen.current_contact == contact_name:
                screen.load_messages_for(contact_name)
        except Exception:
            pass