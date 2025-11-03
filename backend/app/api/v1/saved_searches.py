from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from app.schemas.saved_search import SavedSearch, SavedSearchCreate
from app.services.saved_search_service import (
    SavedSearchService,
    get_saved_search_service,
)
from app.services.audit_service import AuditService, get_audit_service
from app.utils.request import get_client_ip

router = APIRouter()


@router.get("", response_model=list[SavedSearch])
async def list_saved_searches(
    service: SavedSearchService = Depends(get_saved_search_service),
) -> list[SavedSearch]:
    return await service.list_saved_searches()


@router.post("", response_model=SavedSearch, status_code=status.HTTP_201_CREATED)
async def create_saved_search(
    payload: SavedSearchCreate,
    request: Request,
    service: SavedSearchService = Depends(get_saved_search_service),
    audit_service: AuditService = Depends(get_audit_service),
) -> SavedSearch:
    try:
        created = await service.create_saved_search(payload)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    client_ip = get_client_ip(request)
    metadata = {
        "label": "Gespeicherte Suche erstellt",
        "clientIp": client_ip,
        "searchName": created.name,
    }
    metadata = {key: value for key, value in metadata.items() if value}
    result_payload = {
        "savedSearchId": created.id,
        "queryParams": created.query_params,
        "name": created.name,
    }
    if created.dql_query:
        result_payload["dqlQuery"] = created.dql_query
    await audit_service.record_event(
        "saved_search_created",
        metadata=metadata or None,
        result=result_payload,
    )
    return created


@router.delete(
    "/{search_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
)
async def delete_saved_search(
    search_id: str,
    request: Request,
    service: SavedSearchService = Depends(get_saved_search_service),
    audit_service: AuditService = Depends(get_audit_service),
) -> Response:
    existing = await service.get_saved_search(search_id)
    if existing is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Saved search not found.")
    deleted = await service.delete_saved_search(search_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Saved search not found.")

    client_ip = get_client_ip(request)
    metadata = {
        "label": "Gespeicherte Suche gelöscht",
        "clientIp": client_ip,
        "searchName": existing.name,
    }
    metadata = {key: value for key, value in metadata.items() if value}
    result_payload = {
        "savedSearchId": existing.id,
        "queryParams": existing.query_params,
        "name": existing.name,
    }
    if existing.dql_query:
        result_payload["dqlQuery"] = existing.dql_query

    await audit_service.record_event(
        "saved_search_deleted",
        metadata=metadata or None,
        result=result_payload,
    )

    return Response(status_code=status.HTTP_204_NO_CONTENT)
