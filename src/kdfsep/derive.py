"""Purpose separated key derivation helpers."""

import hashlib
import hmac

PURPOSES = ("encrypt", "verify", "wrap", "auth")

LABELS = {
    "encrypt": "kdfsep/encrypt/v1",
    "verify": "kdfsep/verify/v1",
    "wrap": "kdfsep/wrap/v1",
    "auth": "kdfsep/auth/v1",
}

DEFAULT_POLICY = {
    "encrypt": {"min": 16, "max": 64, "default": 32},
    "verify": {"min": 16, "max": 64, "default": 32},
    "wrap": {"min": 16, "max": 32, "default": 32},
    "auth": {"min": 16, "max": 64, "default": 32},
}

MAX_OUTPUT = 64
SALT_MIN = 8

_EXTRACT_TAG = b"kdfsep/extract"
_EXPAND_TAG = b"kdfsep/expand"


def _to_bytes(value, field):
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8")
    raise TypeError(f"{field} must be bytes or str")


def _digest(*parts):
    material = b"".join(parts)
    return hashlib.sha256(material).digest()


def extract(secret, salt):
    material = _to_bytes(secret, "secret")
    salt_material = _to_bytes(salt, "salt")
    if not material:
        raise ValueError("secret must not be empty")
    return _digest(_EXTRACT_TAG, salt_material, material)


def expand(prk, info, length):
    key = _to_bytes(prk, "prk")
    info_bytes = _to_bytes(info, "info")
    if not isinstance(length, int) or isinstance(length, bool):
        raise TypeError("length must be an int")
    if length <= 0:
        raise ValueError("length must be positive")
    if length > MAX_OUTPUT:
        raise ValueError("length is outside the allowed range")

    output = b""
    previous = b""
    counter = 1
    while len(output) < length:
        previous = hmac.new(
            key,
            previous + info_bytes + bytes((counter,)),
            hashlib.sha256,
        ).digest()
        output += previous
        counter += 1
    return output[:length]


def derive(secret, salt, info, length):
    if not isinstance(length, int) or isinstance(length, bool):
        raise TypeError("length must be an int")
    if length <= 0 or length > MAX_OUTPUT:
        raise ValueError("length is outside the allowed range")
    prk = extract(secret, salt)
    info_bytes = _to_bytes(info, "info")
    return expand(prk, info_bytes, length)


def label_for(purpose):
    if purpose in LABELS:
        return LABELS[purpose]
    raise ValueError(f"unknown purpose: {purpose!r}")


def check_length(length, purpose, policy):
    if purpose not in policy:
        return False
    if not isinstance(length, int) or isinstance(length, bool):
        return False
    rule = policy[purpose]
    minimum = rule["min"]
    maximum = rule["max"]
    return minimum <= length <= maximum


def check_purpose(purpose, allowed):
    return purpose in allowed


def validate_config(config):
    issues = []
    if not isinstance(config, dict):
        return ["config must be a mapping"]
    salt = config.get("salt")
    if not salt:
        issues.append("salt is required")
    else:
        salt_length = len(_to_bytes(salt, "salt"))
        if salt_length < SALT_MIN:
            issues.append(
                f"salt must be at least {SALT_MIN} bytes long"
            )
    info = config.get("info")
    if info is None:
        info = config.get("label")
    if not info:
        issues.append("an info label is required")
    purpose = config.get("purpose")
    if purpose is None and isinstance(info, (str, bytes, bytearray)):
        info_text = (
            info
            if isinstance(info, str)
            else bytes(info).decode("utf-8", errors="ignore")
        )
        label_to_purpose = {value: key for key, value in LABELS.items()}
        purpose = info_text if info_text in LABELS else label_to_purpose.get(info_text)
    if purpose is not None:
        if purpose not in LABELS:
            issues.append("purpose is not allowed")
        else:
            policy = config.get("policy", DEFAULT_POLICY)
            purpose_policy = policy.get(purpose, DEFAULT_POLICY[purpose])
            length = config.get("length", purpose_policy["default"])
            if not check_length(length, purpose, {purpose: purpose_policy}):
                issues.append("length is outside the allowed range")
    return issues


def derive_batch(requests, config):
    if not isinstance(requests, list):
        raise TypeError("requests must be a list")
    if not isinstance(config, dict):
        raise TypeError("config must be a mapping")
    salt = config.get("salt")
    if not salt:
        raise ValueError("config requires a salt")
    context = _to_bytes(config.get("context", ""), "context")
    policy = config.get("policy", DEFAULT_POLICY)
    results = {}
    for request in requests:
        purpose = request["purpose"]
        secret = request["secret"]
        if purpose not in LABELS:
            raise ValueError("unknown purpose")
        length = request.get("length", policy[purpose]["default"])
        if not check_length(length, purpose, policy):
            raise ValueError("length is outside the allowed range")
        prk = extract(secret, salt)
        label = label_for(purpose).encode("utf-8")
        results[purpose] = expand(prk, label + context, length)
    return results
