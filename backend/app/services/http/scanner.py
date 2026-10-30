from __future__ import annotations

import httpx
import structlog

from app.core.config import settings
from app.services.http.ssl import get_http_verify

log = structlog.get_logger()

SECRET_HEADER = "X-Scanner-Secret"


async def _log_rejected_secret(response: httpx.Response) -> None:
    if response.status_code == 401:
        log.error(
            "scanner.secret_rejected",
            path=response.url.path,
            secret_configured=bool(settings.sca_scanner_secret),
        )


def scanner_client(timeout: float | httpx.Timeout) -> httpx.AsyncClient:
    """Client for every call to the scanner sidecar, so none goes out without the secret."""
    secret = settings.sca_scanner_secret
    return httpx.AsyncClient(
        timeout=timeout,
        headers={SECRET_HEADER: secret} if secret else None,
        verify=get_http_verify(),
        event_hooks={"response": [_log_rejected_secret]},
    )
