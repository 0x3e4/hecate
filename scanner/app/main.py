from __future__ import annotations

import asyncio
import os
import shutil

from fastapi import FastAPI, HTTPException

from app.malware_detector.known_compromised import serialize_malware_feed
from app.malware_intel_refresh import refresh_now, start_background_refresh
from app.models import CheckRequest, CheckResponse, MalwareFeedEntry, MalwareFeedResponse, ScanMetadata, ScanRequest, ScanResponse, ScannerResult, StatsResponse
from app.scanners import (
    extract_source_archive,
    get_git_commit_sha,
    get_image_digest,
    get_remote_commit_sha,
    run_scanner,
    setup_auth,
)

# Track active scan count
_active_scans = 0

app = FastAPI(title="Hecate Scanner Sidecar", version="1.0.0")

VALID_SCANNERS = {"trivy", "grype", "syft", "osv-scanner", "hecate", "dockle", "dive", "semgrep", "trufflehog"}


_refresh_task = None


@app.on_event("startup")
async def _startup() -> None:
    auth = os.environ.get("SCANNER_AUTH")
    if auth:
        setup_auth(auth)
    # Warm the dynamic malware-intel cache from the backend. Fail-open:
    # any transport error just leaves the static known-compromised list
    # active for HEC-090 detection.
    await refresh_now()
    global _refresh_task
    _refresh_task = start_background_refresh()


@app.on_event("shutdown")
async def _shutdown() -> None:
    global _refresh_task
    if _refresh_task is not None:
        _refresh_task.cancel()
        try:
            await _refresh_task
        except (asyncio.CancelledError, Exception):  # noqa: BLE001
            pass
        _refresh_task = None


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


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
    """Lightweight fingerprint check — returns current digest/commit without scanning."""
    if request.type == "container_image":
        digest = await get_image_digest(request.target)
        return CheckResponse(target=request.target, type=request.type, current_digest=digest)
    elif request.type == "source_repo":
        sha = await get_remote_commit_sha(request.target)
        return CheckResponse(target=request.target, type=request.type, current_commit_sha=sha)
    else:
        raise HTTPException(status_code=400, detail="type must be 'container_image' or 'source_repo'")


@app.get("/malware-feed", response_model=MalwareFeedResponse)
async def malware_feed() -> MalwareFeedResponse:
    """Merged view of the static HEC-090 known-compromised list and the
    runtime-loaded dynamic intel (populated via
    ``update_dynamic_known_compromised``). The backend's user-facing
    ``/v1/malware/malware-feed`` endpoint health-probes this route to
    populate ``scannerAvailable`` on the response.
    """
    raw = serialize_malware_feed()
    return MalwareFeedResponse(
        total=len(raw),
        entries=[MalwareFeedEntry(**e) for e in raw],
    )


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

    source_dir: str | None = None
    if request.source_archive_base64:
        if request.type != "source_repo":
            raise HTTPException(status_code=400, detail="sourceArchiveBase64 is only valid for source_repo scans")
        try:
            source_dir = extract_source_archive(request.source_archive_base64)
        except RuntimeError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

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
                metadata.commit_sha = await get_remote_commit_sha(request.target)
        elif request.type == "container_image":
            metadata.image_digest = await get_image_digest(request.target)
    finally:
        _active_scans = max(0, _active_scans - 1)
        if source_dir:
            shutil.rmtree(source_dir, ignore_errors=True)

    return ScanResponse(target=request.target, type=request.type, results=results, metadata=metadata)
