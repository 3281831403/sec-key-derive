"""Public surface for purpose separated key derivation."""

from .derive import (
    DEFAULT_POLICY,
    LABELS,
    MAX_OUTPUT,
    PURPOSES,
    SALT_MIN,
    check_length,
    check_purpose,
    derive,
    derive_batch,
    expand,
    extract,
    label_for,
    validate_config,
)

__all__ = [
    "DEFAULT_POLICY",
    "LABELS",
    "MAX_OUTPUT",
    "PURPOSES",
    "SALT_MIN",
    "check_length",
    "check_purpose",
    "derive",
    "derive_batch",
    "expand",
    "extract",
    "label_for",
    "validate_config",
]