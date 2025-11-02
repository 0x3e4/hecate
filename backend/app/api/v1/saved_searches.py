from fastapi import APIRouter, Depends, HTTPException, Response, status

from app.schemas.saved_search import SavedSearch, SavedSearchCreate
from app.services.saved_search_service import (
    SavedSearchService,
    get_saved_search_service,
)

router = APIRouter()


@router.get("", response_model=list[SavedSearch])
async def list_saved_searches(
    service: SavedSearchService = Depends(get_saved_search_service),
) -> list[SavedSearch]:
    return await service.list_saved_searches()


@router.post("", response_model=SavedSearch, status_code=status.HTTP_201_CREATED)
async def create_saved_search(
    payload: SavedSearchCreate,
    service: SavedSearchService = Depends(get_saved_search_service),
) -> SavedSearch:
    try:
        return await service.create_saved_search(payload)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.delete(
    "/{search_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
)
async def delete_saved_search(
    search_id: str,
    service: SavedSearchService = Depends(get_saved_search_service),
) -> Response:
    deleted = await service.delete_saved_search(search_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Saved search not found.")
    return Response(status_code=status.HTTP_204_NO_CONTENT)
