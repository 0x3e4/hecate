"""Every call to the scanner sidecar carries the shared secret."""
from __future__ import annotations

import inspect
from pathlib import Path

import httpx
import pytest

from app.api.v1 import status, version
from app.core.config import settings
from app.services import scan_service
from app.services.http import scanner
from app.services.http.scanner import SECRET_HEADER, scanner_client


async def test_the_secret_is_sent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "sca_scanner_secret", "s3cret")
    async with scanner_client(timeout=1) as client:
        assert client.headers[SECRET_HEADER] == "s3cret"


async def test_no_header_without_a_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "sca_scanner_secret", None)
    async with scanner_client(timeout=1) as client:
        assert SECRET_HEADER not in client.headers


def test_no_sidecar_call_bypasses_the_client() -> None:
    # A call on a plain client would work until someone sets the secret.
    assert "httpx.AsyncClient(" not in Path(inspect.getfile(scan_service)).read_text(encoding="utf-8")
    assert "httpx.AsyncClient(" not in Path(inspect.getfile(status)).read_text(encoding="utf-8")
    assert "scanner_client(" in inspect.getsource(version._probe_scanner)


@pytest.mark.parametrize(("code", "reachable"), [(200, True), (401, False)])
async def test_a_rejected_secret_does_not_read_as_a_healthy_scanner(
    monkeypatch: pytest.MonkeyPatch, code: int, reachable: bool
) -> None:
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(request.url.path)
        return httpx.Response(code, json={})

    monkeypatch.setattr(settings, "sca_enabled", True)
    monkeypatch.setattr(status, "scanner_client", lambda timeout: httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    result = await status.scanner_health()
    assert result.reachable is reachable
    # /health is open, so it could not tell a wrong secret from a working one.
    assert requested == ["/stats"]


async def test_a_rejected_secret_is_logged(monkeypatch: pytest.MonkeyPatch) -> None:
    events: list[str] = []
    monkeypatch.setattr(scanner.log, "error", lambda event, **_: events.append(event))
    await scanner._log_rejected_secret(httpx.Response(401, request=httpx.Request("GET", "http://s/stats")))
    await scanner._log_rejected_secret(httpx.Response(200, request=httpx.Request("GET", "http://s/stats")))
    assert events == ["scanner.secret_rejected"]
