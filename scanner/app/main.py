from __future__ import annotations

import asyncio
import logging
import os
import shutil
import time
import tomllib
import uuid
from pathlib import Path

# Configure root logger BEFORE importing modules that grab their own logger.
# Uvicorn doesn't touch the root logger, so application loggers like
# `app.scanners` would otherwise inherit WARNING with no handler attached
# and `logger.info()` calls would silently disappear. basicConfig adds a
# StreamHandler to root only if none exists yet, which is exactly the gap
# uvicorn leaves.
#
# Level honors the deployment-wide `LOG_LEVEL` env var (same one the
# backend's configure_logging() reads), so a single `LOG_LEVEL=DEBUG` in
# `.env` flips both services into verbose mode together.
_log_level_name = os.environ.get("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, _log_level_name, logging.INFO),
    format="%(asctime)s %(levelname)-7s %(name)s %(message)s",
)

from fastapi import FastAPI, HTTPException

from app.models import (
    CheckRequest,
    CheckResponse,
    CleanupSourceRequest,
    CleanupSourceResponse,
    PrepareSourceRequest,
    PrepareSourceResponse,
    ScanMetadata,
    ScanRequest,
    ScanResponse,
    ScannerResult,
    StatsResponse,
)
from app.scanners import (
    _clone_repo,
    extract_source_archive,
    get_git_commit_sha,
    get_image_digest,
    get_remote_commit_sha,
    run_scanner,
    setup_auth,
)

logger = logging.getLogger("app.scanner_sidecar")

# Track active scan count
_active_scans = 0

# Shared source checkouts prepared once per scan via /prepare-source and reused
# across all scanners of that scan (so a source repo is cloned once, not once
# per scanner). token -> {"dir": str, "created_at": float, "refcount": int}.
# Single event-loop access, so plain dict ops are safe without a lock.
_source_checkouts: dict[str, dict] = {}


def _source_checkout_ttl() -> int:
    """Idle TTL (seconds) after which an unreferenced checkout is reaped.

    Pure crash-leak backstop: a live checkout has refcount > 0 and is never
    reaped regardless of age. Default 7200 comfortably exceeds the longest
    plausible scan wall-clock (resource wait + concurrent grype/devskim)."""
    raw = os.environ.get("SOURCE_CHECKOUT_TTL_SECONDS")
    if not raw:
        return 7200
    try:
        val = int(raw)
    except ValueError:
        return 7200
    return val if val > 0 else 7200


_PYPROJECT_CANDIDATES = (
    Path("/scanner/pyproject.toml"),
    Path(__file__).resolve().parents[1] / "pyproject.toml",
    Path("pyproject.toml"),
)


def _read_version() -> str:
    """Read the scanner version from pyproject.toml so bump-version.sh
    propagates to the runtime self-report (FastAPI docs + /version)."""
    for path in _PYPROJECT_CANDIDATES:
        try:
            with path.open("rb") as f:
                data = tomllib.load(f)
        except (FileNotFoundError, OSError, tomllib.TOMLDecodeError):
            continue
        version = data.get("tool", {}).get("poetry", {}).get("version")
        if isinstance(version, str) and version:
            return version
    return "0.0.0"


_VERSION = _read_version()

app = FastAPI(title="Hecate Scanner Sidecar", version=_VERSION)

VALID_SCANNERS = {"trivy", "grype", "syft", "osv-scanner", "hecate", "dockle", "dive", "semgrep", "trufflehog", "devskim"}


async def _reap_source_checkouts_once() -> int:
    """One reaping pass: remove unreferenced checkouts older than the TTL.

    A checkout leaks only when the backend crashes between /prepare-source and
    /cleanup-source. Such an entry has refcount 0 (all /scan calls finished or
    never arrived) and ages past the TTL; entries with refcount > 0 are in active
    use and are never reaped, so the reaper can't rmtree a dir out from under a
    running scanner. Returns the number of checkouts removed."""
    ttl = _source_checkout_ttl()
    now = time.monotonic()
    stale = [
        token
        for token, entry in list(_source_checkouts.items())
        if entry.get("refcount", 0) <= 0 and (now - entry.get("created_at", now)) > ttl
    ]
    for token in stale:
        entry = _source_checkouts.pop(token, None)
        if not entry:
            continue
        logger.warning(
            "source_checkout.reaped_stale token=%s dir=%s age=%.0fs",
            token, entry.get("dir"), now - entry.get("created_at", now),
        )
        await asyncio.to_thread(shutil.rmtree, entry["dir"], ignore_errors=True)
    return len(stale)


async def _reap_stale_source_checkouts() -> None:
    """Background loop that periodically reaps leaked source checkouts."""
    while True:
        try:
            await asyncio.sleep(300)
            await _reap_source_checkouts_once()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 — reaper must never die on a transient error
            logger.exception("source_checkout.reaper_error")


@app.on_event("startup")
async def _startup() -> None:
    auth = os.environ.get("SCANNER_AUTH")
    if auth:
        setup_auth(auth)
    asyncio.create_task(_reap_stale_source_checkouts())


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


_BUILD_SHA_FILE = Path("/scanner/app/.build_sha")


def _read_build_sha() -> str | None:
    """Resolve the scanner's build SHA. File baked at image build time wins;
    otherwise fall back to the HECATE_BUILD_SHA env var (for local dev).
    """
    try:
        raw = _BUILD_SHA_FILE.read_text().strip()
    except (FileNotFoundError, PermissionError, OSError):
        raw = ""
    if not raw:
        raw = (os.environ.get("HECATE_BUILD_SHA") or "").strip()
    return raw or None


@app.get("/version")
async def version() -> dict[str, str | None]:
    """Self-report identity for the in-app Support page. Sibling of the
    backend's /api/v1/version endpoint, queried over the compose network.
    """
    return {"buildSha": _read_build_sha(), "version": _VERSION}


def _read_int(path: str) -> int | None:
    try:
        with open(path) as f:
            val = f.read().strip()
            return int(val) if val != "max" else None
    except (OSError, ValueError):
        return None


@app.get("/stats", response_model=StatsResponse)
async def stats() -> StatsResponse:
    """Return scanner container resource usage (cgroup-aware)."""
    mem_used = 0
    mem_limit = 0

    # cgroup v2 (preferred)
    cg2_current = _read_int("/sys/fs/cgroup/memory.current")
    cg2_max = _read_int("/sys/fs/cgroup/memory.max")
    # cgroup v1 fallback
    cg1_usage = _read_int("/sys/fs/cgroup/memory/memory.usage_in_bytes")
    cg1_limit = _read_int("/sys/fs/cgroup/memory/memory.limit_in_bytes")

    if cg2_current is not None:
        mem_used = cg2_current
        mem_limit = cg2_max or 0
    elif cg1_usage is not None:
        mem_used = cg1_usage
        mem_limit = cg1_limit or 0

    # If cgroup limit is unreasonably large (no limit set), fall back to host meminfo
    if mem_limit == 0 or mem_limit > 1024 * 1024 * 1024 * 1024:
        try:
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        mem_limit = int(line.split()[1]) * 1024
                        break
        except OSError:
            pass

    try:
        disk = shutil.disk_usage("/tmp")
        tmp_total, tmp_used, tmp_free = disk.total, disk.used, disk.free
    except OSError:
        tmp_total = tmp_used = tmp_free = 0

    return StatsResponse(
        memory_used_bytes=mem_used,
        memory_limit_bytes=mem_limit,
        tmp_disk_total_bytes=tmp_total,
        tmp_disk_used_bytes=tmp_used,
        tmp_disk_free_bytes=tmp_free,
        active_scans=_active_scans,
    )


@app.post("/check", response_model=CheckResponse)
async def check(request: CheckRequest) -> CheckResponse:
    """Lightweight fingerprint check — returns current digest/commit without scanning.

    Runs concurrently with in-flight scans: the probes are network-bound
    (git ls-remote / skopeo inspect, both 20 s subprocess-capped) and use
    negligible CPU, so gating them on scan concurrency caused every target
    past the first two to land in the DB as a spurious check_failed_skipped
    each auto-scan tick.
    """
    if request.type == "container_image":
        digest, error = await get_image_digest(request.target)
        return CheckResponse(
            target=request.target, type=request.type,
            current_digest=digest, error=error,
        )
    elif request.type == "source_repo":
        sha, error = await get_remote_commit_sha(request.target)
        return CheckResponse(
            target=request.target, type=request.type,
            current_commit_sha=sha, error=error,
        )
    else:
        raise HTTPException(status_code=400, detail="type must be 'container_image' or 'source_repo'")


@app.post("/prepare-source", response_model=PrepareSourceResponse)
async def prepare_source(request: PrepareSourceRequest) -> PrepareSourceResponse:
    """Clone a source repo once and register it for reuse across a scan's scanners.

    Returns a sourceToken the backend threads into every /scan call so the repo
    is cloned once instead of once per scanner. A clone failure is returned as a
    200 with an `error` field (not a 4xx) so the backend can surface the clone
    stderr and distinguish it from the sidecar being unreachable. The token is
    owned by /cleanup-source (and the idle reaper as a backstop) — /scan never
    deletes a token-resolved checkout."""
    if request.type != "source_repo":
        raise HTTPException(status_code=400, detail="prepare-source is only valid for source_repo scans")
    try:
        checkout_dir = await _clone_repo(request.target)
    except RuntimeError as exc:
        return PrepareSourceResponse(source_token=None, error=str(exc))
    token = uuid.uuid4().hex
    _source_checkouts[token] = {"dir": checkout_dir, "created_at": time.monotonic(), "refcount": 0}
    return PrepareSourceResponse(source_token=token)


@app.post("/cleanup-source", response_model=CleanupSourceResponse)
async def cleanup_source(request: CleanupSourceRequest) -> CleanupSourceResponse:
    """Remove a prepared source checkout. Idempotent — an unknown/expired token
    returns removed=false without error. rmtree runs off the event loop."""
    entry = _source_checkouts.pop(request.source_token, None)
    if not entry:
        return CleanupSourceResponse(removed=False)
    await asyncio.to_thread(shutil.rmtree, entry["dir"], ignore_errors=True)
    return CleanupSourceResponse(removed=True)


@app.post("/scan", response_model=ScanResponse)
async def scan(request: ScanRequest) -> ScanResponse:
    global _active_scans
    invalid = set(request.scanners) - VALID_SCANNERS
    if invalid:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid scanners: {', '.join(sorted(invalid))}. Valid: {', '.join(sorted(VALID_SCANNERS))}",
        )

    if request.type not in ("container_image", "source_repo"):
        raise HTTPException(status_code=400, detail="type must be 'container_image' or 'source_repo'")

    # Two mutually-exclusive ways to get a working tree: an uploaded archive
    # (owned by this /scan call, extracted fresh each time) or a shared checkout
    # prepared once via /prepare-source (owned by /cleanup-source — never deleted
    # here). Archive takes precedence; the token is a strict elif so a request
    # can never both extract an archive and resolve a token.
    source_dir: str | None = None
    owns_source_dir = False
    token_entry: dict | None = None
    if request.source_archive_base64:
        if request.type != "source_repo":
            raise HTTPException(status_code=400, detail="sourceArchiveBase64 is only valid for source_repo scans")
        try:
            source_dir = extract_source_archive(request.source_archive_base64)
            owns_source_dir = True
        except RuntimeError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    elif request.source_token:
        token_entry = _source_checkouts.get(request.source_token)
        if not token_entry:
            raise HTTPException(status_code=400, detail="Unknown or expired sourceToken")
        source_dir = token_entry["dir"]
        # Refresh + refcount so the idle reaper never removes a checkout with
        # live /scan calls against it.
        token_entry["created_at"] = time.monotonic()
        token_entry["refcount"] = token_entry.get("refcount", 0) + 1

    results: list[ScannerResult] = []
    metadata = ScanMetadata()
    _active_scans += 1
    try:
        for scanner_name in request.scanners:
            result = await run_scanner(scanner_name, request.target, request.type, source_dir=source_dir)
            results.append(result)

        # Collect metadata
        if request.type == "source_repo":
            if source_dir:
                metadata.commit_sha = await get_git_commit_sha(source_dir)
            else:
                metadata.commit_sha, _ = await get_remote_commit_sha(request.target)
        elif request.type == "container_image":
            metadata.image_digest, _ = await get_image_digest(request.target)
    finally:
        _active_scans = max(0, _active_scans - 1)
        # Only delete a checkout this call owns (uploaded archive). A
        # token-resolved checkout is released back to /cleanup-source — just drop
        # the refcount so the reaper can reclaim it if the backend crashed.
        if owns_source_dir and source_dir:
            shutil.rmtree(source_dir, ignore_errors=True)
        elif token_entry is not None:
            token_entry["refcount"] = max(0, token_entry.get("refcount", 0) - 1)

    return ScanResponse(target=request.target, type=request.type, results=results, metadata=metadata)
