import time

from lanmess_files.tui import LanMessApp


class _FakeDB:
    def __init__(self, value):
        self.value = value

    def get_auto_lock_seconds(self):
        return self.value


class _FakeApp:
    def __init__(self, value, name):
        self.db = _FakeDB(value)
        self.user_name = name
        self._global_last_activity = time.time()


_FakeApp._should_auto_lock = LanMessApp._should_auto_lock


def test_should_auto_lock_false_when_recent():
    app = _FakeApp(900, "alice")
    assert not app._should_auto_lock()


def test_should_auto_lock_true_after_idle():
    app = _FakeApp(900, "alice")
    app._global_last_activity = time.time() - 1000
    assert app._should_auto_lock()


def test_should_auto_lock_false_when_disabled():
    app = _FakeApp(0, "alice")
    app._global_last_activity = time.time() - 10000
    assert not app._should_auto_lock()


def test_should_auto_lock_false_when_locked():
    app = _FakeApp(900, None)
    app._global_last_activity = time.time() - 10000
    assert not app._should_auto_lock()


def test_should_auto_lock_exactly_at_boundary():
    app = _FakeApp(900, "alice")
    now = time.time()
    app._global_last_activity = now - 900
    assert not app._should_auto_lock(now)
    app._global_last_activity = now - 901
    assert app._should_auto_lock(now)