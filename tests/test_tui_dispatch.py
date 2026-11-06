import inspect

from lanmess_files.tui import MainScreen


def test_action_clear_chat_is_sync():
    assert not inspect.iscoroutinefunction(
        MainScreen.action_clear_chat
    )


def test_action_clear_all_is_sync():
    assert not inspect.iscoroutinefunction(
        MainScreen.action_clear_all
    )


def test_action_delete_contact_is_sync():
    assert not inspect.iscoroutinefunction(
        MainScreen.action_delete_contact
    )


def test_action_stop_chat_is_sync():
    assert not inspect.iscoroutinefunction(
        MainScreen.action_stop_chat
    )


def test_action_verify_is_sync():
    assert not inspect.iscoroutinefunction(
        MainScreen.action_verify
    )


def test_action_start_chat_is_async():
    assert inspect.iscoroutinefunction(
        MainScreen.action_start_chat
    )


def test_action_accept_is_async():
    assert inspect.iscoroutinefunction(
        MainScreen.action_accept
    )


def test_action_reject_is_async():
    assert inspect.iscoroutinefunction(
        MainScreen.action_reject
    )


def test_menu_has_all_action_ids():
    from lanmess_files.tui import MenuScreen

    expected = {
        "m-start",
        "m-accept",
        "m-reject",
        "m-stop",
        "m-verify",
        "m-clear",
        "m-clearall",
        "m-delete",
        "m-code",
        "m-lock",
        "m-help",
        "m-reset",
        "m-close",
    }
    src = inspect.getsource(MenuScreen.compose)
    for eid in expected:
        assert eid in src, f"missing menu button id: {eid}"


def test_dispatch_sync_handles_clear_and_clearall():
    src = inspect.getsource(MainScreen._dispatch_sync)
    assert "action_clear_chat" in src
    assert "action_clear_all" in src
    assert "action_delete_contact" in src