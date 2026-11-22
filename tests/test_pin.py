import pytest

from lanmess_files.tui import _check_pin_strength


def test_valid_pin():
    assert _check_pin_strength("CorrectHorse123!") is None


def test_valid_pin_mixed():
    assert _check_pin_strength("Tr0ub4dor&3xyzQ") is None


def test_valid_pin_all_classes():
    assert _check_pin_strength("Abcdefgh1234!") is None
    assert _check_pin_strength("Abcdefghijk1!") is None
    assert _check_pin_strength("Abcdefgh123!") is None
    assert _check_pin_strength("AbcDEFGH123!") is None


def test_empty_pin_rejected():
    assert _check_pin_strength("") is not None


def test_short_pin_rejected():
    assert _check_pin_strength("Ab1!") is not None


def test_pin_too_long_rejected():
    long_pin = "Aa1!" * 40
    assert _check_pin_strength(long_pin) is not None


def test_pin_missing_lowercase():
    assert _check_pin_strength("ABCDEFGH1234!") is not None


def test_pin_missing_uppercase():
    assert _check_pin_strength("abcdefgh1234!") is not None


def test_pin_missing_digit():
    assert _check_pin_strength("Abcdefghijk!X") is not None


def test_pin_missing_symbol():
    assert _check_pin_strength("Abcdefgh1234") is not None


def test_pin_too_few_distinct_chars():
    assert _check_pin_strength("Aa1!Aa1!Aa1!") is not None


def test_pin_four_identical_in_row():
    assert _check_pin_strength("Aaaaaaaa123!") is not None


def test_pin_repeated_pattern():
    assert _check_pin_strength("Virenvirenviren1!") is not None
    assert _check_pin_strength("AbcAbcAbc123!") is not None
    assert _check_pin_strength("PasswordPassword1!") is not None


def test_user_example_rejected():
    assert _check_pin_strength("virenvirenviren1!") is not None
    assert _check_pin_strength("Virenvirenviren1!") is not None
    assert _check_pin_strength("virenvirenviren!") is not None