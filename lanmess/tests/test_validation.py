import time

import pytest

from lanmess_files.config import REPLAY_WINDOW_SECONDS
from lanmess_files.tui import LanMessApp


def test_valid_name_accepts():
    assert LanMessApp._valid_name(None, "alice")
    assert LanMessApp._valid_name(None, "a")
    assert LanMessApp._valid_name(None, "a" * 40)
    assert LanMessApp._valid_name(None, "User Name 123")


def test_valid_name_rejects_empty():
    assert not LanMessApp._valid_name(None, "")


def test_valid_name_rejects_too_long():
    assert not LanMessApp._valid_name(None, "a" * 41)


def test_valid_name_rejects_control_chars():
    assert not LanMessApp._valid_name(None, "a\x00b")
    assert not LanMessApp._valid_name(None, "a\nb")
    assert not LanMessApp._valid_name(None, "a\tb")


def test_valid_name_rejects_non_str():
    assert not LanMessApp._valid_name(None, None)
    assert not LanMessApp._valid_name(None, 123)
    assert not LanMessApp._valid_name(None, b"alice")


def test_valid_hex_accepts():
    assert LanMessApp._valid_hex(None, "00" * 32, 32)
    assert LanMessApp._valid_hex(None, "aa" * 32, 32)
    assert LanMessApp._valid_hex(None, "FF" * 32, 32)


def test_valid_hex_rejects_wrong_length():
    assert not LanMessApp._valid_hex(None, "00" * 31, 32)
    assert not LanMessApp._valid_hex(None, "00" * 33, 32)


def test_valid_hex_rejects_invalid_chars():
    assert not LanMessApp._valid_hex(None, "zz" * 32, 32)
    assert not LanMessApp._valid_hex(None, "  " * 32, 32)


def test_valid_hex_rejects_non_str():
    assert not LanMessApp._valid_hex(None, None, 32)
    assert not LanMessApp._valid_hex(None, b"00" * 32, 32)


def test_valid_code_accepts():
    assert LanMessApp._valid_code(None, "12345678")
    assert LanMessApp._valid_code(None, "00000000")


def test_valid_code_rejects_wrong_length():
    assert not LanMessApp._valid_code(None, "1234567")
    assert not LanMessApp._valid_code(None, "123456789")


def test_valid_code_rejects_non_digit():
    assert not LanMessApp._valid_code(None, "1234567a")
    assert not LanMessApp._valid_code(None, "1234 678")


def test_valid_code_rejects_non_str():
    assert not LanMessApp._valid_code(None, None)
    assert not LanMessApp._valid_code(None, 12345678)


def test_valid_timestamp_now():
    now_ms = int(time.time() * 1000)
    assert LanMessApp._valid_timestamp(None, now_ms)


def test_valid_timestamp_within_window():
    now_ms = int(time.time() * 1000)
    half = REPLAY_WINDOW_SECONDS * 500
    assert LanMessApp._valid_timestamp(None, now_ms - half)
    assert LanMessApp._valid_timestamp(None, now_ms + half)


def test_valid_timestamp_outside_window():
    now_ms = int(time.time() * 1000)
    over = (REPLAY_WINDOW_SECONDS + 10) * 1000
    assert not LanMessApp._valid_timestamp(None, now_ms - over)
    assert not LanMessApp._valid_timestamp(None, now_ms + over)


def test_valid_timestamp_rejects_zero_and_negative():
    assert not LanMessApp._valid_timestamp(None, 0)
    assert not LanMessApp._valid_timestamp(None, -1)


def test_valid_timestamp_rejects_non_int():
    assert not LanMessApp._valid_timestamp(None, None)
    assert not LanMessApp._valid_timestamp(None, "123")
    assert not LanMessApp._valid_timestamp(None, 1.5)