from __future__ import annotations

import re
from typing import Any

from fastapi import APIRouter, HTTPException

from app.repositories.license_policy_repository import LicensePolicyRepository
from app.schemas.license_policy import (
    LicenseGroupsResponse,
    LicensePolicyCreateRequest,
    LicensePolicyListResponse,
    LicensePolicyResponse,
    LicensePolicyUpdateRequest,
)
from app.services.license_compliance_service import (
    COPYLEFT_LICENSES,
    PERMISSIVE_LICENSES,
    WEAK_COPYLEFT_LICENSES,
)

router = APIRouter()

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _make_slug(name: str) -> str:
    return _SLUG_RE.sub("-", name.lower()).strip("-")[:80]


def _map_policy(doc: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(doc["_id"]),
        "name": doc.get("name", ""),
        "description": doc.get("description"),
        "allowed": doc.get("allowed", []),
        "denied": doc.get("denied", []),
        "reviewed": doc.get("reviewed", []),
        "defaultAction": doc.get("default_action", "warn"),
        "isDefault": doc.get("is_default", False),
        "createdAt": doc.get("created_at"),
        "updatedAt": doc.get("updated_at"),
    }


async def _get_repo() -> LicensePolicyRepository:
    return await LicensePolicyRepository.create()


@router.get("", response_model=LicensePolicyListResponse)
async def list_policies() -> LicensePolicyListResponse:
    repo = await _get_repo()
    docs = await repo.list_all()
    items = [LicensePolicyResponse(**_map_policy(d)) for d in docs]
    return LicensePolicyListResponse(items=items, total=len(items))


@router.post("", response_model=LicensePolicyResponse, status_code=201)
async def create_policy(request: LicensePolicyCreateRequest) -> LicensePolicyResponse:
    repo = await _get_repo()
    policy_id = _make_slug(request.name)
    if not policy_id:
        raise HTTPException(status_code=400, detail="Invalid policy name")

    existing = await repo.get(policy_id)
    if existing:
        raise HTTPException(status_code=409, detail="Policy with this name already exists")

    data = {
        "name": request.name,
        "description": request.description,
        "allowed": request.allowed,
        "denied": request.denied,
        "reviewed": request.reviewed,
        "default_action": request.default_action,
        "is_default": request.is_default,
    }

    if request.is_default:
        await repo.set_default(policy_id)

    doc = await repo.insert(policy_id, data)
    return LicensePolicyResponse(**_map_policy(doc))


@router.get("/groups", response_model=LicenseGroupsResponse)
async def get_license_groups() -> LicenseGroupsResponse:
    """Return built-in SPDX license groups for quick policy creation."""
    return LicenseGroupsResponse(
        permissive=sorted(PERMISSIVE_LICENSES),
        weakCopyleft=sorted(WEAK_COPYLEFT_LICENSES),
        copyleft=sorted(COPYLEFT_LICENSES),
    )


@router.get("/{policy_id}", response_model=LicensePolicyResponse)
async def get_policy(policy_id: str) -> LicensePolicyResponse:
    repo = await _get_repo()
    doc = await repo.get(policy_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Policy not found")
    return LicensePolicyResponse(**_map_policy(doc))


@router.put("/{policy_id}", response_model=LicensePolicyResponse)
async def update_policy(
    policy_id: str, request: LicensePolicyUpdateRequest
) -> LicensePolicyResponse:
    repo = await _get_repo()
    existing = await repo.get(policy_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Policy not found")

    updates: dict[str, Any] = {}
    if request.name is not None:
        updates["name"] = request.name
    if request.description is not None:
        updates["description"] = request.description
    if request.allowed is not None:
        updates["allowed"] = request.allowed
    if request.denied is not None:
        updates["denied"] = request.denied
    if request.reviewed is not None:
        updates["reviewed"] = request.reviewed
    if request.default_action is not None:
        updates["default_action"] = request.default_action
    if request.is_default is not None:
        updates["is_default"] = request.is_default
        if request.is_default:
            await repo.set_default(policy_id)

    if updates:
        await repo.update(policy_id, updates)

    doc = await repo.get(policy_id)
    return LicensePolicyResponse(**_map_policy(doc))  # type: ignore[arg-type]


@router.delete("/{policy_id}", status_code=204)
async def delete_policy(policy_id: str) -> None:
    repo = await _get_repo()
    deleted = await repo.delete(policy_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Policy not found")


@router.post("/{policy_id}/set-default", response_model=LicensePolicyResponse)
async def set_default_policy(policy_id: str) -> LicensePolicyResponse:
    repo = await _get_repo()
    existing = await repo.get(policy_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Policy not found")

    await repo.set_default(policy_id)
    doc = await repo.get(policy_id)
    return LicensePolicyResponse(**_map_policy(doc))  # type: ignore[arg-type]
