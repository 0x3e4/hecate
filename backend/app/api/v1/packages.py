"""Pre-install package check: ``GET /api/v1/packages/check``.

A read endpoint for AI coding agents (a pre-tool hook before ``npm install`` /
``pip install``) and CI: malicious, vulnerable, freshly published, taken over
or unmaintained packages. See app/services/package_check_service.py.
"""

from __future__ import annotations

import time

from fastapi import APIRouter, HTTPException, Query, Request

from app.core.auth_context import get_auth_context
from app.core.auth_throttle import client_key
from app.core.config import settings
from app.db.mongo import get_database
from app.schemas.package_check import PackageCheckResponse
from app.services.package_check_service import PackageCheckError, check_package
from app.services.supply_chain_service import get_supply_chain_service
from app.utils.request import get_security_client_ip

router = APIRouter()

# Per-client token buckets for callers without a session. Every uncached check
# takes a slot on the one deps.dev rate limit all users share, so one anonymous
# client sending unique names delayed everyone else's checks past a hook's
# timeout. In-memory and single-process, like the auth throttle.
_buckets: dict[str, tuple[float, float]] = {}
_MAX_TRACKED_CLIENTS = 10_000


def _allow(key: str, now: float | None = None) -> bool:
    rate = settings.package_check_rate_per_minute
    if rate <= 0:
        return True
    now = time.monotonic() if now is None else now
    tokens, last = _buckets.get(key, (float(rate), now))
    tokens = min(float(rate), tokens + (now - last) * rate / 60.0)
    if len(_buckets) >= _MAX_TRACKED_CLIENTS and key not in _buckets:
        # Drop the clients whose buckets have refilled; they carry no state.
        full = [k for k, (t, at) in _buckets.items() if t + (now - at) * rate / 60.0 >= rate]
        for k in full:
            del _buckets[k]
    if tokens < 1.0:
        _buckets[key] = (tokens, now)
        return False
    _buckets[key] = (tokens - 1.0, now)
    return True


@router.get("/check", response_model=PackageCheckResponse)
async def check_package_endpoint(
    request: Request,
    ecosystem: str = Query(description="npm, pypi, go, maven, cargo, nuget, rubygems or packagist", max_length=20),
    name: str = Query(description="Package name (npm @scope/name, Maven group:artifact, Go module path)", max_length=300),
    version: str | None = Query(default=None, description="Version to check; omitted = the latest release", max_length=100),
) -> PackageCheckResponse:
    """Verdict ``block`` | ``warn`` | ``ok`` with reasons, advisories and release signals."""
    if (await get_auth_context(request)).user is None:
        if not _allow(client_key(get_security_client_ip(request) or "unknown")):
            raise HTTPException(
                status_code=429,
                detail="Too many package checks from this client; try again in a minute.",
                headers={"Retry-After": "30"},
            )
    database = await get_database()
    supply_chain = await get_supply_chain_service() if settings.sca_release_info_enabled else None
    try:
        result = await check_package(
            ecosystem, name, version,
            vuln_collection=database[settings.mongo_vulnerabilities_collection],
            supply_chain=supply_chain,
            max_items=100,
        )
    except PackageCheckError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return PackageCheckResponse.model_validate(result)
