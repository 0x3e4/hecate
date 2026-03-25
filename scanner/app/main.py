from __future__ import annotations

import os
import shutil

from fastapi import FastAPI, HTTPException

from app.models import ScanMetadata, ScanRequest, ScanResponse, ScannerResult
from app.scanners import (
    extract_source_archive,
    get_git_commit_sha,
    get_image_digest,
    run_scanner,
    setup_auth,
)

app = FastAPI(title="Hecate Scanner Sidecar", version="0.1.0")

VALID_SCANNERS = {"trivy", "grype", "syft", "osv-scanner", "hecate"}


@app.on_event("startup")
async def _startup() -> None:
    auth = os.environ.get("SCANNER_AUTH")
    if auth:
        setup_auth(auth)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/scan", response_model=ScanResponse)
async def scan(request: ScanRequest) -> ScanResponse:
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
    try:
        for scanner_name in request.scanners:
            result = await run_scanner(scanner_name, request.target, request.type, source_dir=source_dir)
            results.append(result)

        # Collect metadata
        if request.type == "source_repo" and source_dir:
            metadata.commit_sha = await get_git_commit_sha(source_dir)
        elif request.type == "container_image":
            metadata.image_digest = await get_image_digest(request.target)
    finally:
        if source_dir:
            shutil.rmtree(source_dir, ignore_errors=True)

    return ScanResponse(target=request.target, type=request.type, results=results, metadata=metadata)
