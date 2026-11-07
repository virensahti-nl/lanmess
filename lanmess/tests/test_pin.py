import pytest

from lanmess_files.tui import _check_pin_strength


def test_valid_pin():
    assert _check_pin_strength("CorrectHorse123!") is None


def test_empty_pin_rejected():
    assert _check_pin_strength("") is not None


def test_short_pin_rejected():
    assert _check_pin_strength("Ab1!") is not None


def test_pin_too_long_rejected():
    long_pin = "Aa1!" * 40
    assert _check_pin_strength(long_pin) is not None


def test_pin_too_few_classes():
    assert _check_pin_strength("abcdefghijkl") is not None
    assert _check_pin_strength("abcdefghijk1") is not None


def test_pin_too_few_distinct_chars():
    assert _check_pin_strength("Aa1!Aa1!Aa1!") is not None


def test_pin_lower_upper_digit():
    assert _check_pin_strength("Abcdefgh1234") is None


def test_pin_lower_upper_symbol():
    assert _check_pin_strength("Abcdefghijk!") is None


def test_pin_lower_digit_symbol():
    assert _check_pin_strength("abcdefgh123!") is None


def test_pin_upper_digit_symbol():
    assert _check_pin_strength("ABCDEFGH123!") is None