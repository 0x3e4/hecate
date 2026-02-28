from __future__ import annotations

import os

from fastapi import FastAPI, HTTPException

from app.models import ScanRequest, ScanResponse, ScannerResult
from app.scanners import run_scanner, setup_auth

app = FastAPI(title="Hecate Scanner Sidecar", version="0.1.0")

VALID_SCANNERS = {"trivy", "grype", "syft", "osv-scanner"}


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

    results: list[ScannerResult] = []
    for scanner_name in request.scanners:
        result = await run_scanner(scanner_name, request.target, request.type)
        results.append(result)

    return ScanResponse(target=request.target, type=request.type, results=results)
