"""Password hashing for per-target write passwords.

Uses the stdlib (``hashlib.pbkdf2_hmac``) so no extra dependency is needed. The
stored format is a single self-describing string::

    pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>

Only used for the per-target write passwords stored in MongoDB. The global
``SYSTEM_PASSWORD`` / ``AI_ANALYSIS_PASSWORD`` / ``SCA_API_KEY`` come from the
environment and are compared with :func:`secret_equals` (constant-time) — these
per-target secrets stored at rest are hashed instead.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

_ALGORITHM = "pbkdf2_sha256"
_ITERATIONS = 200_000
_SALT_BYTES = 16


def secret_equals(provided: str | None, expected: str | None) -> bool:
    """Constant-time comparison for plaintext shared secrets.

    Used for the env-configured ``SYSTEM_PASSWORD`` / ``AI_ANALYSIS_PASSWORD`` /
    ``SCA_API_KEY`` checks (replacing plain ``==``, which leaks length/prefix via
    timing). Returns ``False`` when either side is missing so an unset secret
    never matches. Encodes to bytes so non-ASCII secrets compare safely.
    """
    if not expected or provided is None:
        return False
    return hmac.compare_digest(provided.encode("utf-8"), expected.encode("utf-8"))


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
