"""Public contract tests for purpose separated key derivation."""

import pytest

from kdfsep import (
    DEFAULT_POLICY,
    LABELS,
    check_length,
    derive,
    derive_batch,
    label_for,
)

SECRET = b"correct horse battery staple"
SALT = b"0123456789abcdef"
OTHER_SALT = b"fedcba9876543210"


def test_derive_is_deterministic():
    first = derive(SECRET, SALT, LABELS["encrypt"], 32)
    second = derive(SECRET, SALT, LABELS["encrypt"], 32)
    third = derive(SECRET, OTHER_SALT, LABELS["encrypt"], 32)
    assert first == second
    assert first != third


def test_different_purposes_have_different_keys():
    encrypt_key = derive(SECRET, SALT, LABELS["encrypt"], 32)
    verify_key = derive(SECRET, SALT, LABELS["verify"], 32)
    assert len(encrypt_key) == 32
    assert len(verify_key) == 32
    assert encrypt_key != verify_key


def test_check_length_enforces_policy_bounds():
    assert check_length(32, "encrypt", DEFAULT_POLICY) is True
    assert check_length(15, "encrypt", DEFAULT_POLICY) is False
    assert check_length(0, "encrypt", DEFAULT_POLICY) is False
    assert check_length(65, "encrypt", DEFAULT_POLICY) is False


def test_label_for_rejects_unknown_purpose():
    assert label_for("encrypt") == LABELS["encrypt"]
    with pytest.raises(ValueError):
        label_for("administrator")


def test_batch_two_purposes_are_independent():
    requests = [
        {"purpose": "encrypt", "secret": SECRET, "length": 32},
        {"purpose": "verify", "secret": SECRET, "length": 32},
    ]
    result = derive_batch(requests, {"salt": SALT, "context": "session-1"})
    assert set(result) == {"encrypt", "verify"}
    assert len(result["encrypt"]) == 32
    assert len(result["verify"]) == 32
    assert result["encrypt"] != result["verify"]