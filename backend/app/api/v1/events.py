"""SSE endpoint for real-time job / ingestion events."""

from __future__ import annotations

import asyncio
import json

import structlog
from fastapi import APIRouter
from starlette.requests import Request
from starlette.responses import StreamingResponse

from app.services.event_bus import JobEvent, get_event_bus

log = structlog.get_logger()

router = APIRouter()


async def _event_generator(request: Request):
    """Yield SSE-formatted events to the client."""
    bus = get_event_bus()
    queue = bus.subscribe()
    try:
        # Send an initial keepalive so the client knows the connection is live
        yield ": connected\n\n"

        while True:
            # Check if client disconnected
            if await request.is_disconnected():
                break

            try:
                event: JobEvent = await asyncio.wait_for(queue.get(), timeout=15.0)
                data = json.dumps(event.to_dict(), default=str)
                yield f"event: {event.event_type}\ndata: {data}\n\n"
            except asyncio.TimeoutError:
                # Send keepalive comment to prevent proxy/browser timeout
                yield ": keepalive\n\n"
    except asyncio.CancelledError:
        pass
    finally:
        bus.unsubscribe(queue)


@router.get("")
async def stream_events(request: Request) -> StreamingResponse:
    """Server-Sent Events stream for ingestion / sync job status updates."""
    return StreamingResponse(
        _event_generator(request),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
