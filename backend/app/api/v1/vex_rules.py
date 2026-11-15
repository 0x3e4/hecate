"""Automatic VEX triage rules. Mounted with the admin write gate (routes.py)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException

from app.schemas.vex_rule import (
    VexRuleAction,
    VexRuleApplyResponse,
    VexRuleConditions,
    VexRuleListResponse,
    VexRulePreset,
    VexRulePresetListResponse,
    VexRuleRequest,
    VexRuleResponse,
)
from app.services.vex_rule_service import PRESETS, VexRuleService, get_vex_rule_service

router = APIRouter()


def _map_rule(doc: dict[str, Any], counts: dict[str, int]) -> VexRuleResponse:
    rule_id = str(doc["_id"])
    return VexRuleResponse(
        id=rule_id,
        name=doc.get("name", ""),
        description=doc.get("description"),
        enabled=bool(doc.get("enabled")),
        priority=int(doc.get("priority", 100)),
        conditions=VexRuleConditions.model_validate(doc.get("conditions") or {}),
        action=VexRuleAction.model_validate(doc.get("action") or {"vex_status": "under_investigation"}),
        preset=doc.get("preset"),
        finding_count=counts.get(rule_id, 0),
        created_at=doc.get("created_at"),
        updated_at=doc.get("updated_at"),
    )


def _payload(request: VexRuleRequest) -> dict[str, Any]:
    if request.conditions.is_empty():
        raise HTTPException(status_code=400, detail="A rule needs at least one condition.")
    return {
        "name": request.name,
        "description": (request.description or "").strip() or None,
        "enabled": request.enabled,
        "priority": request.priority,
        "conditions": request.conditions.model_dump(),
        "action": request.action.model_dump(),
        "preset": request.preset,
    }


async def _service() -> VexRuleService:
    return await get_vex_rule_service()


@router.get("", response_model=VexRuleListResponse)
async def list_rules() -> VexRuleListResponse:
    service = await _service()
    docs = await service.rule_repo.list_all()
    counts = await service.finding_counts()
    items = [_map_rule(d, counts) for d in docs]
    return VexRuleListResponse(items=items, total=len(items))


@router.get("/presets", response_model=VexRulePresetListResponse)
async def list_presets() -> VexRulePresetListResponse:
    return VexRulePresetListResponse(items=[
        VexRulePreset(
            key=p["key"],
            name=p["name"],
            description=p["description"],
            priority=p.get("priority", 100),
            conditions=VexRuleConditions.model_validate(p["conditions"]),
            action=VexRuleAction.model_validate(p["action"]),
        )
        for p in PRESETS
    ])


@router.post("/apply", response_model=VexRuleApplyResponse)
async def apply_rules() -> VexRuleApplyResponse:
    """Apply the enabled rules to the latest completed scan of every target."""
    service = await _service()
    return VexRuleApplyResponse(**await service.apply_all())


@router.post("", response_model=VexRuleResponse, status_code=201)
async def create_rule(request: VexRuleRequest) -> VexRuleResponse:
    service = await _service()
    doc = await service.rule_repo.insert(_payload(request))
    if doc.get("enabled"):
        await service.apply_all()
    return _map_rule(doc, await service.finding_counts())


@router.put("/{rule_id}", response_model=VexRuleResponse)
async def update_rule(rule_id: str, request: VexRuleRequest) -> VexRuleResponse:
    service = await _service()
    existing = await service.rule_repo.get(rule_id)
    if not existing:
        raise HTTPException(status_code=404, detail="VEX rule not found")
    doc = await service.rule_repo.replace(rule_id, _payload(request))
    if doc is None:
        raise HTTPException(status_code=404, detail="VEX rule not found")
    if not doc.get("enabled"):
        # Disabled: its statuses go everywhere, not only in the latest scans.
        await service.retire_rule(rule_id)
    if doc.get("enabled") or existing.get("enabled"):
        await service.apply_all()
    return _map_rule(doc, await service.finding_counts())


@router.delete("/{rule_id}", status_code=204)
async def delete_rule(rule_id: str) -> None:
    service = await _service()
    existing = await service.rule_repo.get(rule_id)
    if not existing:
        raise HTTPException(status_code=404, detail="VEX rule not found")
    await service.rule_repo.delete(rule_id)
    await service.retire_rule(rule_id)
    if existing.get("enabled"):
        # Another rule may now match what this one held.
        await service.apply_all()
