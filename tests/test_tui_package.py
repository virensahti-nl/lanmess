import asyncio
import base64
import hashlib
import importlib
import inspect
import json
import os
import time
from unittest.mock import AsyncMock, patch

from lanmess_files.config import CONTROL_SIG_PREFIX
from lanmess_files.crypto import (
    ed_public_to_bytes,
    generate_ed25519_private,
    sign_bytes,
    x25519_generate,
)
from lanmess_files.database import Database
from lanmess_files.tui import LanMessApp


def test_public_names_importable():
    from lanmess_files.tui import (
        AddByIpScreen,
        AddCodeScreen,
        ConfirmScreen,
        ContactItem,
        HelpScreen,
        LanMessApp,
        MainScreen,
        MenuScreen,
        MyAddressScreen,
        PanicSettingsScreen,
        SearchScreen,
        StartupScreen,
        VerifyScreen,
        _check_pin_strength,
        _now_ms,
        _valid_ipv4,
        _valid_port,
        get_local_ips,
        send_request,
    )
    assert LanMessApp is not None
    assert MainScreen is not None
    assert ContactItem is not None
    assert callable(_check_pin_strength)
    assert callable(_now_ms)
    assert callable(_valid_ipv4)
    assert callable(_valid_port)
    assert callable(get_local_ips)
    assert callable(send_request)


def test_helpers_reexported():
    from lanmess_files.tui import (
        _check_pin_strength,
        _valid_ipv4,
        _valid_port,
        get_local_ips,
    )
    from lanmess_files.tui.helpers import (
        _check_pin_strength as orig_check,
        _valid_ipv4 as orig_v4,
        _valid_port as orig_port,
        get_local_ips as orig_ips,
    )
    assert _check_pin_strength is orig_check
    assert _valid_ipv4 is orig_v4
    assert _valid_port is orig_port
    assert get_local_ips is orig_ips


def test_contact_item_reexported():
    from lanmess_files.tui import ContactItem
    from lanmess_files.tui.contact_item import (
        ContactItem as OrigContactItem,
    )
    assert ContactItem is OrigContactItem


def test_main_screen_reexported():
    from lanmess_files.tui import MainScreen
    from lanmess_files.tui.main_screen import (
        MainScreen as OrigMainScreen,
    )
    assert MainScreen is OrigMainScreen


def test_screens_reexported():
    from lanmess_files.tui import (
        AddByIpScreen,
        AddCodeScreen,
        ConfirmScreen,
        HelpScreen,
        MenuScreen,
        MyAddressScreen,
        PanicSettingsScreen,
        SearchScreen,
        StartupScreen,
        VerifyScreen,
    )
    from lanmess_files.tui.screens import (
        AddByIpScreen as OrigAddByIp,
        AddCodeScreen as OrigAddCode,
        ConfirmScreen as OrigConfirm,
        HelpScreen as OrigHelp,
        MenuScreen as OrigMenu,
        MyAddressScreen as OrigMyAddress,
        PanicSettingsScreen as OrigPanic,
        SearchScreen as OrigSearch,
        StartupScreen as OrigStartup,
        VerifyScreen as OrigVerify,
    )
    assert AddByIpScreen is OrigAddByIp
    assert AddCodeScreen is OrigAddCode
    assert ConfirmScreen is OrigConfirm
    assert HelpScreen is OrigHelp
    assert MenuScreen is OrigMenu
    assert MyAddressScreen is OrigMyAddress
    assert PanicSettingsScreen is OrigPanic
    assert SearchScreen is OrigSearch
    assert StartupScreen is OrigStartup
    assert VerifyScreen is OrigVerify


def test_submodules_importable():
    for mod in (
        "lanmess_files.tui",
        "lanmess_files.tui.app",
        "lanmess_files.tui.app_handlers",
        "lanmess_files.tui.helpers",
        "lanmess_files.tui.contact_item",
        "lanmess_files.tui.main_screen",
        "lanmess_files.tui.screens",
        "lanmess_files.tui.screens.confirm",
        "lanmess_files.tui.screens.search",
        "lanmess_files.tui.screens.add_code",
        "lanmess_files.tui.screens.add_by_ip",
        "lanmess_files.tui.screens.my_address",
        "lanmess_files.tui.screens.panic",
        "lanmess_files.tui.screens.menu",
        "lanmess_files.tui.screens.verify",
        "lanmess_files.tui.screens.help",
        "lanmess_files.tui.screens.startup",
    ):
        importlib.import_module(mod)


def test_handlers_mixin_binds_to_app():
    from lanmess_files.tui.app_handlers import HandlersMixin

    assert issubclass(LanMessApp, HandlersMixin)
    for name in (
        "handle_incoming",
        "_handle_add_request",
        "_handle_add_accept",
        "_handle_add_reject",
        "_handle_rotate",
        "_handle_chat_start",
        "_handle_chat_accept",
        "_handle_chat_reject",
        "_handle_chat_stop",
        "_handle_clear_request",
        "_handle_clear_accept",
        "_handle_clear_reject",
        "_handle_presence",
        "_handle_typing",
        "_handle_message",
        "_verify_peer_sig_no_touch",
        "_verify_peer_sig",
        "_deferred_refresh",
    ):
        assert hasattr(LanMessApp, name), name
        method = getattr(LanMessApp, name)
        assert inspect.iscoroutinefunction(method), name


def test_package_send_request_patchable():
    from lanmess_files import tui as tui_pkg

    original = tui_pkg.send_request
    assert callable(original)
    sentinel = AsyncMock()
    try:
        tui_pkg.send_request = sentinel
        assert tui_pkg.send_request is sentinel
    finally:
        tui_pkg.send_request = original


def test_app_module_send_request_delegates():
    from lanmess_files import tui as tui_pkg
    from lanmess_files.tui import app as app_mod

    sentinel = {"sentinel": True}

    async def fake_send(*a, **kw):
        return sentinel

    original = tui_pkg.send_request
    tui_pkg.send_request = fake_send
    try:
        result = asyncio.run(
            app_mod.send_request("ip", 1, {})
        )
        assert result is sentinel
    finally:
        tui_pkg.send_request = original


def test_handlers_module_send_request_delegates():
    from lanmess_files import tui as tui_pkg
    from lanmess_files.tui import app_handlers as handlers_mod

    sentinel = {"sentinel": True}

    async def fake_send(*a, **kw):
        return sentinel

    original = tui_pkg.send_request
    tui_pkg.send_request = fake_send
    try:
        result = asyncio.run(
            handlers_mod.send_request("ip", 1, {})
        )
        assert result is sentinel
    finally:
        tui_pkg.send_request = original


def test_patching_package_affects_add_contact_by_ip(
    db_path,
):
    db = Database(db_path)
    db.create_identity(
        name="alice",
        master=os.urandom(32),
        group_key=os.urandom(32),
        ed_private_hex="00" * 32,
        ed_public_hex="11" * 32,
        totp_secret_hex="22" * 20,
        tcp_port=50510,
        x25519_private_hex="33" * 32,
        x25519_public_hex="44" * 32,
    )

    class _App:
        def __init__(self):
            self.db = db
            self.user_name = "alice"
            self.ed_private = generate_ed25519_private()
            self.ed_public = self.ed_private.public_key()
            self.x25519_private = x25519_generate()
            self.x25519_public = (
                self.x25519_private.public_key()
            )
            self.tcp_port = 50510
            self.notifications = []

        def notify(self, msg, **kw):
            self.notifications.append(msg)

        def _audit(self, *a, **k):
            pass

        def _refresh_main(self, *a, **k):
            pass

        def _refresh_visible_messages(self, *a, **k):
            pass

        def _touch_heard(self, name):
            pass

    _App._valid_name = LanMessApp._valid_name
    _App._valid_hex = LanMessApp._valid_hex
    _App._valid_timestamp = LanMessApp._valid_timestamp
    _App._check_signed = LanMessApp._check_signed
    _App._signed = LanMessApp._signed
    _App._build_add_request_payload = (
        LanMessApp._build_add_request_payload
    )
    _App._process_add_response = (
        LanMessApp._process_add_response
    )

    app = _App()

    with patch(
        "lanmess_files.tui.send_request",
        new_callable=AsyncMock,
    ) as mock_send:
        mock_send.return_value = None
        result = asyncio.run(
            LanMessApp.add_contact_by_ip(
                app, "10.1.2.3", 9999, "12345678"
            )
        )
        assert result is False
        mock_send.assert_called_once()
        args = mock_send.call_args[0]
        assert args[0] == "10.1.2.3"
        assert args[1] == 9999


def test_patching_package_affects_send_chat_message(
    db_path,
):
    db = Database(db_path)
    db.create_identity(
        name="alice",
        master=os.urandom(32),
        group_key=os.urandom(32),
        ed_private_hex="00" * 32,
        ed_public_hex="11" * 32,
        totp_secret_hex="22" * 20,
        tcp_port=50510,
        x25519_private_hex="33" * 32,
        x25519_public_hex="44" * 32,
    )
    db.upsert_contact(
        "bob", "10.0.0.5", 50520, "aa" * 32, "bb" * 32
    )
    db.set_contact_state(
        "bob",
        chat_started=1,
        session_established=1,
        pending=0,
        send_chain_key_hex="00" * 32,
        recv_chain_key_hex="11" * 32,
        send_counter=0,
        recv_counter=0,
    )

    class _App:
        def __init__(self):
            self.db = db
            self.user_name = "alice"
            self.ed_private = generate_ed25519_private()
            self.ed_public = self.ed_private.public_key()
            self._outbox = {}
            self._contact_locks = {}
            self._last_activity = {}
            self._last_heard = {}
            self._peer_offline = {}
            self.notifications = []

        def notify(self, msg, **kw):
            self.notifications.append(msg)

        def _resolve_peer_address(self, contact):
            return ("127.0.0.1", 50510)

        def _get_contact_lock(self, name):
            if name not in self._contact_locks:
                self._contact_locks[name] = asyncio.Lock()
            return self._contact_locks[name]

        def _mark_offline(self, name):
            pass

        def _refresh_main(self):
            pass

        def _refresh_visible_messages(self):
            pass

        def _touch_activity(self, name):
            pass

        def _touch_heard(self, name):
            pass

    app = _App()

    with patch(
        "lanmess_files.tui.send_request",
        new_callable=AsyncMock,
    ) as mock_send:
        mock_send.return_value = {"type": "OK"}
        ok = asyncio.run(
            LanMessApp.send_chat_message(
                app, "bob", "hello"
            )
        )
        assert ok is True
        mock_send.assert_called_once()
        msgs = db.get_messages("bob")
        assert len(msgs) == 1
        assert msgs[0]["content"] == "hello"


def test_patching_package_affects_handle_presence(db_path):
    db = Database(db_path)
    db.create_identity(
        name="alice",
        master=os.urandom(32),
        group_key=os.urandom(32),
        ed_private_hex="00" * 32,
        ed_public_hex="11" * 32,
        totp_secret_hex="22" * 20,
        tcp_port=50510,
        x25519_private_hex="33" * 32,
        x25519_public_hex="44" * 32,
    )
    peer_sk = generate_ed25519_private()
    peer_ed_hex = ed_public_to_bytes(
        peer_sk.public_key()
    ).hex()
    db.upsert_contact(
        "bob", "10.0.0.5", 50520, peer_ed_hex, "bb" * 32
    )

    now_ms = int(time.time() * 1000)
    fields = {
        "type": "PRESENCE",
        "from_name": "bob",
        "status": "online",
        "timestamp": now_ms,
    }
    body = dict(fields)
    data = CONTROL_SIG_PREFIX + json.dumps(
        body, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    sig = base64.b64encode(
        sign_bytes(peer_sk, data)
    ).decode("ascii")
    msg = {**body, "signature": sig}

    class _App:
        def __init__(self):
            self.db = db
            self.user_name = "alice"
            self._last_heard = {}
            self._peer_offline = {}
            self._peer_typing = {}
            self._pending_rotates = {
                "bob": {"type": "ROTATE"}
            }
            self.notifications = []

        def notify(self, msg, **kw):
            self.notifications.append(msg)

        def _touch_heard(self, name):
            self._last_heard[name] = time.time()
            self._peer_offline.pop(name, None)

        def _mark_offline(self, name):
            self._peer_offline[name] = time.time()
            self._last_heard[name] = 0

        def _refresh_main(self):
            pass

        def _apply_peer_ip(self, msg, name):
            pass

        def _resolve_peer_address(self, contact):
            return ("127.0.0.1", 50510)

    _App._valid_name = LanMessApp._valid_name
    _App._valid_hex = LanMessApp._valid_hex
    _App._valid_timestamp = LanMessApp._valid_timestamp
    _App._check_signed = LanMessApp._check_signed
    _App._verify_peer_sig_no_touch = (
        LanMessApp._verify_peer_sig_no_touch
    )
    _App._verify_peer_sig = LanMessApp._verify_peer_sig
    _App._handle_presence = LanMessApp._handle_presence

    app = _App()

    with patch(
        "lanmess_files.tui.send_request",
        new_callable=AsyncMock,
    ) as mock_send:
        mock_send.return_value = {"type": "OK"}
        resp = asyncio.run(
            LanMessApp._handle_presence(app, msg)
        )
        assert resp.get("type") == "OK"
        mock_send.assert_called_once()
        assert "bob" not in app._pending_rotates