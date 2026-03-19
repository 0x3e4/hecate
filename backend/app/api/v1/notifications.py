from fastapi import APIRouter, Body, Depends, HTTPException

from app.schemas.notification import (
    NotificationChannelAddRequest,
    NotificationChannelListResponse,
    NotificationChannelResponse,
    NotificationRuleCreate,
    NotificationRuleListResponse,
    NotificationRuleResponse,
    NotificationStatusResponse,
    NotificationTemplateCreate,
    NotificationTemplateListResponse,
    NotificationTemplateResponse,
    NotificationTestResponse,
)
from app.services.notification_service import NotificationService, get_notification_service

router = APIRouter()


# --- Health / Test ---


@router.get("/status", response_model=NotificationStatusResponse)
async def notification_status(
    service: NotificationService = Depends(get_notification_service),
) -> NotificationStatusResponse:
    info = await service.health()
    return NotificationStatusResponse(
        enabled=bool(info.get("enabled", False)),
        reachable=bool(info.get("reachable", False)),
        url="",
        tags=None,
    )


@router.post("/test", response_model=NotificationTestResponse)
async def send_test_notification(
    tag: str | None = Body(default=None, embed=True),
    service: NotificationService = Depends(get_notification_service),
) -> NotificationTestResponse:
    if not service.enabled:
        return NotificationTestResponse(
            success=False,
            message="Notifications are disabled. Set NOTIFICATIONS_ENABLED=true to enable.",
        )
    ok = await service.send_test(tag=tag)
    if ok:
        return NotificationTestResponse(success=True, message="Test notification sent successfully.")
    return NotificationTestResponse(success=False, message="Failed to send test notification. Check channels and Apprise service.")


# --- Channel Management ---


@router.get("/channels", response_model=NotificationChannelListResponse)
async def list_channels(
    service: NotificationService = Depends(get_notification_service),
) -> NotificationChannelListResponse:
    docs = await service.list_channels()
    items = [
        NotificationChannelResponse(
            id=str(d["_id"]),
            url=d["url"],
            tag=d.get("tag", "all"),
            created_at=d.get("created_at"),
        )
        for d in docs
    ]
    return NotificationChannelListResponse(items=items)


@router.post("/channels", response_model=NotificationChannelResponse, status_code=201)
async def add_channel(
    payload: NotificationChannelAddRequest,
    service: NotificationService = Depends(get_notification_service),
) -> NotificationChannelResponse:
    doc = await service.add_channel(payload.url, tag=payload.tag)
    return NotificationChannelResponse(
        id=str(doc["_id"]),
        url=doc["url"],
        tag=doc.get("tag", "all"),
        created_at=doc["created_at"],
    )


@router.delete("/channels/{channel_id}", status_code=204)
async def remove_channel(
    channel_id: str,
    service: NotificationService = Depends(get_notification_service),
) -> None:
    deleted = await service.remove_channel(channel_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Channel not found")


# --- Notification Rules CRUD ---


@router.get("/rules", response_model=NotificationRuleListResponse)
async def list_rules(
    service: NotificationService = Depends(get_notification_service),
) -> NotificationRuleListResponse:
    rules = await service.list_rules()
    return NotificationRuleListResponse(total=len(rules), items=rules)


@router.post("/rules", response_model=NotificationRuleResponse, status_code=201)
async def create_rule(
    payload: NotificationRuleCreate,
    service: NotificationService = Depends(get_notification_service),
) -> NotificationRuleResponse:
    valid_types = {"event", "saved_search", "vendor", "product", "dql"}
    if payload.rule_type not in valid_types:
        raise HTTPException(status_code=400, detail=f"Invalid rule_type. Must be one of: {', '.join(sorted(valid_types))}")
    return await service.create_rule(payload)


@router.get("/rules/{rule_id}", response_model=NotificationRuleResponse)
async def get_rule(
    rule_id: str,
    service: NotificationService = Depends(get_notification_service),
) -> NotificationRuleResponse:
    rule = await service.get_rule(rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule


@router.put("/rules/{rule_id}", response_model=NotificationRuleResponse)
async def update_rule(
    rule_id: str,
    payload: NotificationRuleCreate,
    service: NotificationService = Depends(get_notification_service),
) -> NotificationRuleResponse:
    result = await service.update_rule(rule_id, payload)
    if result is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    return result


@router.delete("/rules/{rule_id}", status_code=204)
async def delete_rule(
    rule_id: str,
    service: NotificationService = Depends(get_notification_service),
) -> None:
    deleted = await service.delete_rule(rule_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Rule not found")


# --- Message Templates CRUD ---


VALID_EVENT_KEYS = {"new_vulnerabilities", "scan_completed", "scan_failed", "sync_failed", "watch_rule_match"}


@router.get("/templates", response_model=NotificationTemplateListResponse)
async def list_templates(
    service: NotificationService = Depends(get_notification_service),
) -> NotificationTemplateListResponse:
    templates = await service.list_templates()
    return NotificationTemplateListResponse(items=templates)


@router.post("/templates", response_model=NotificationTemplateResponse, status_code=201)
async def create_template(
    payload: NotificationTemplateCreate,
    service: NotificationService = Depends(get_notification_service),
) -> NotificationTemplateResponse:
    if payload.event_key not in VALID_EVENT_KEYS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid event_key. Must be one of: {', '.join(sorted(VALID_EVENT_KEYS))}",
        )
    return await service.create_template(payload)


@router.put("/templates/{template_id}", response_model=NotificationTemplateResponse)
async def update_template(
    template_id: str,
    payload: NotificationTemplateCreate,
    service: NotificationService = Depends(get_notification_service),
) -> NotificationTemplateResponse:
    if payload.event_key not in VALID_EVENT_KEYS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid event_key. Must be one of: {', '.join(sorted(VALID_EVENT_KEYS))}",
        )
    result = await service.update_template(template_id, payload)
    if result is None:
        raise HTTPException(status_code=404, detail="Template not found")
    return result


@router.delete("/templates/{template_id}", status_code=204)
async def delete_template(
    template_id: str,
    service: NotificationService = Depends(get_notification_service),
) -> None:
    deleted = await service.delete_template(template_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Template not found")
