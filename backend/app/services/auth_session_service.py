"""Server-side web sessions for the OIDC login.

The browser holds an opaque random value in an httpOnly cookie; MongoDB holds
its SHA-256 with what the gates need (subject, issuer, name, email, role) and
the ID token for the IdP's logout hint. No access or refresh token is kept: a
lapsed session means signing in again, which also re-reads the role.
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog

from app.core.config import settings
from app.repositories.auth_session_repository import AuthSessionRepository

log = structlog.get_logger()

LOGIN_STATE_TTL = timedelta(minutes=10)
# last_seen_at is written at most this often, not on every request.
_TOUCH_INTERVAL = timedelta(seconds=60)


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _aware(value: Any) -> datetime | None:
    if not isinstance(value, datetime):
        return None
    return value if value.tzinfo else value.replace(tzinfo=UTC)


class AuthSessionService:
    def __init__(self, repository: AuthSessionRepository) -> None:
        self.repository = repository

    async def create_login_state(self, *, state: str, nonce: str, code_verifier: str, return_to: str) -> str:
        """Remember a started login; the returned value goes into a short-lived cookie."""
        token = secrets.token_urlsafe(32)
        now = datetime.now(UTC)
        await self.repository.insert(
            {
                "_id": f"login:{_hash(token)}",
                "kind": "login",
                "state": state,
                "nonce": nonce,
                "code_verifier": code_verifier,
                "return_to": return_to,
                "created_at": now,
                "expires_at": now + LOGIN_STATE_TTL,
            }
        )
        return token

    async def consume_login_state(self, token: str) -> dict[str, Any] | None:
        """The pending login for this browser, once: a replayed callback finds nothing."""
        document = await self.repository.pop(f"login:{_hash(token)}")
        if document is None or document.get("kind") != "login":
            return None
        expires = _aware(document.get("expires_at"))
        if expires is None or expires <= datetime.now(UTC):
            return None
        return document

    async def create_session(
        self,
        *,
        sub: str,
        issuer: str,
        name: str,
        email: str | None,
        role: str,
        id_token: str | None,
    ) -> tuple[str, datetime]:
        token = secrets.token_urlsafe(32)
        now = datetime.now(UTC)
        expires = now + timedelta(hours=max(1, settings.auth_session_lifetime_hours))
        await self.repository.insert(
            {
                "_id": f"session:{_hash(token)}",
                "kind": "session",
                "sub": sub,
                "issuer": issuer,
                "name": name,
                "email": email,
                "role": role,
                "id_token": id_token,
                "created_at": now,
                "last_seen_at": now,
                "expires_at": expires,
            }
        )
        return token, expires

    async def get_session(self, token: str) -> dict[str, Any] | None:
        """The live session for a cookie value, or ``None`` (unknown, expired or idle)."""
        if not token or len(token) > 200:
            return None
        session_id = f"session:{_hash(token)}"
        document = await self.repository.get(session_id)
        if document is None or document.get("kind") != "session":
            return None
        now = datetime.now(UTC)
        expires = _aware(document.get("expires_at"))
        if expires is None or expires <= now:
            return None
        last_seen = _aware(document.get("last_seen_at")) or now
        idle = settings.auth_session_idle_minutes
        if idle > 0 and now - last_seen > timedelta(minutes=idle):
            try:
                await self.repository.pop(session_id)
            except Exception as exc:  # noqa: BLE001 - the session is dead either way
                log.warning("auth.session_idle_cleanup_failed", error=repr(exc))
            return None
        if now - last_seen > _TOUCH_INTERVAL:
            try:
                await self.repository.touch(session_id, now)
            except Exception as exc:  # noqa: BLE001 - a missed timestamp must not log anyone out
                log.warning("auth.session_touch_failed", error=repr(exc))
        return document

    async def delete_session(self, token: str) -> dict[str, Any] | None:
        if not token or len(token) > 200:
            return None
        return await self.repository.pop(f"session:{_hash(token)}")


_service: AuthSessionService | None = None


async def get_auth_session_service() -> AuthSessionService:
    global _service
    if _service is None:
        _service = AuthSessionService(await AuthSessionRepository.create())
    return _service
