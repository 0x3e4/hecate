"""Password hashing for per-target write passwords.

Uses the stdlib (``hashlib.pbkdf2_hmac``) so no extra dependency is needed. The
stored format is a single self-describing string::

    pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>

Only used for the per-target write passwords stored in MongoDB. The global
``SYSTEM_PASSWORD`` / ``AI_ANALYSIS_PASSWORD`` come from the environment and are
compared in plaintext elsewhere — these are operator-entered secrets stored at
rest, so they are hashed.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

_ALGORITHM = "pbkdf2_sha256"
_ITERATIONS = 200_000
_SALT_BYTES = 16


def hash_password(password: str, *, iterations: int = _ITERATIONS) -> str:
    """Hash a plaintext password into the self-describing storage format."""
    salt = secrets.token_bytes(_SALT_BYTES)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"{_ALGORITHM}${iterations}${salt.hex()}${derived.hex()}"


def verify_password(password: str, stored: str | None) -> bool:
    """Constant-time check of a plaintext password against a stored hash.

    Returns ``False`` for any malformed / empty stored value instead of raising,
    so callers can treat "no usable hash" as "not authorized".
    """
    if not password or not stored:
        return False
    try:
        algorithm, iterations_str, salt_hex, hash_hex = stored.split("$")
    except (ValueError, AttributeError):
        return False
    if algorithm != _ALGORITHM:
        return False
    try:
        iterations = int(iterations_str)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
    except ValueError:
        return False
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(derived, expected)
