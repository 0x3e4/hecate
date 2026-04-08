from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import structlog

from app.core.config import settings
from app.repositories.cpe_repository import CPERepository
from app.repositories.ingestion_log_repository import IngestionLogRepository
from app.repositories.ingestion_state_repository import IngestionStateRepository
from app.services.ingestion.job_tracker import JobTracker
from app.services.ingestion.cpe_client import CPEClient

log = structlog.get_logger()

STATE_KEY = "cpe"


class CPEPipeline:
    def __init__(self, *, client: CPEClient | None = None) -> None:
        self.client = client or CPEClient()

    async def sync(self, limit: int | None = None, *, initial_sync: bool = False) -> dict[str, int]:
        state_repo = await IngestionStateRepository.create()
        tracker = JobTracker(state_repo)
        effective_limit = self._resolve_limit(limit)
        job_name = "cpe_initial_sync" if initial_sync else "cpe_sync"
        label = "CPE Initial Sync" if initial_sync else "CPE Sync"
        ctx = await tracker.start(
            job_name,
            limit=effective_limit,
            initial_sync=initial_sync,
            label=label,
        )

        ingested = 0
        failures = 0
        latest_timestamp: datetime | None = None

        timeout_minutes = settings.ingestion_running_timeout_minutes
        timeout_seconds = timeout_minutes * 60 if timeout_minutes and timeout_minutes > 0 else None
        timed_out = False

        processed_total = 0
        last_progress_log = datetime.now(tz=UTC)
        progress_interval = 500
        log_repo: IngestionLogRepository | None = None

        try:
            last_run = await state_repo.get_timestamp(STATE_KEY)
            repo = await CPERepository.create()

            async with asyncio.timeout(timeout_seconds):  # None = no timeout
                async for record in self.client.iter_cpe_records(last_modified_after=last_run):
                    parsed = _normalize_cpe_record(record)
                    if not parsed:
                        failures += 1
                    else:
                        await repo.upsert(parsed)
                        ingested += 1

                        if parsed.get("lastModified") and isinstance(parsed["lastModified"], datetime):
                            ts = parsed["lastModified"].astimezone(UTC)
                            if not latest_timestamp or ts > latest_timestamp:
                                latest_timestamp = ts

                    processed_total += 1
                    now = datetime.now(tz=UTC)
                    if (
                        processed_total % progress_interval == 0
                        or (now - last_progress_log).total_seconds() >= 60
                    ):
                        progress_payload = {
                            "processed": processed_total,
                            "ingested": ingested,
                            "failures": failures,
                            "limit": effective_limit,
                        }
                        await state_repo.update_state(
                            f"job:{ctx.name}",
                            {
                                "status": "running",
                                "progress": progress_payload,
                                "last_progress_at": now,
                            },
                        )
                        if ctx.log_id is not None:
                            if log_repo is None:
                                log_repo = await IngestionLogRepository.create()
                            await log_repo.update_progress(ctx.log_id, progress_payload)
                        log.info("cpe_pipeline.progress", **progress_payload)
                        last_progress_log = now

                    if effective_limit is not None and ingested >= effective_limit:
                        break

        except TimeoutError:
            timed_out = True
            log.warning(
                "cpe_pipeline.timeout",
                timeout_seconds=timeout_seconds,
                ingested=ingested,
                failures=failures,
            )

        except Exception as exc:
            log.exception("cpe_pipeline.sync_failed", error=str(exc), ingested=ingested, failures=failures)
            await tracker.fail(ctx, str(exc))
            raise

        if latest_timestamp:
            await state_repo.set_timestamp(STATE_KEY, latest_timestamp)

        result = {
            "ingested": ingested,
            "failures": failures,
            "limit": effective_limit,
            "initial_sync": initial_sync,
            "timed_out": timed_out,
        }
        await tracker.finish(ctx, **result)
        log.info("cpe_pipeline.sync_complete", **result)
        return result

    async def close(self) -> None:
        await self.client.close()

    @staticmethod
    def _resolve_limit(explicit_limit: int | None) -> int | None:
        configured_limit = settings.cpe_max_records_per_run
        if configured_limit is not None and configured_limit <= 0:
            configured_limit = None

        if explicit_limit is None:
            return configured_limit
        if explicit_limit <= 0:
            return None
        return explicit_limit


def _normalize_cpe_record(record: dict) -> dict | None:  # type: ignore[override]
    product_record = record.get("cpe") or record.get("cpeMatchString")
    if not isinstance(product_record, dict):
        product_record = {
            key: record.get(key)
            for key in ("cpeName", "cpe23Uri", "title", "vendor", "product", "version")
            if record.get(key)
        }
    if isinstance(product_record, dict):
        base = product_record
    else:
        base = record

    cpe_name = base.get("cpe23Uri") or base.get("cpeName")
    if not isinstance(cpe_name, str):
        return None

    metadata = record.get("cpeNameId") or {}
    last_modified = None
    if isinstance(record.get("lastModified"), str):
        try:
            last_modified = datetime.fromisoformat(record["lastModified"].replace("Z", "+00:00")).astimezone(UTC)
        except ValueError:
            last_modified = None

    vendor = base.get("vendor") or _parse_cpe_uri_component(cpe_name, 3)
    product = base.get("product") or _parse_cpe_uri_component(cpe_name, 4)
    version = base.get("version") or _parse_cpe_uri_component(cpe_name, 5)

    return {
        "cpeName": cpe_name,
        "title": _extract_title(record),
        "vendor": vendor,
        "product": product,
        "version": version,
        "deprecated": bool(record.get("deprecated")),
        "cpeNameId": metadata if isinstance(metadata, dict) else None,
        "lastModified": last_modified,
    }


def _extract_title(record: dict) -> str | None:
    titles = record.get("titles")
    if isinstance(titles, list):
        for entry in titles:
            if isinstance(entry, dict) and entry.get("lang", "en").lower() == "en":
                value = entry.get("title")
                if isinstance(value, str):
                    return value
    return None


def _parse_cpe_uri_component(cpe_uri: str, index: int) -> str | None:
    try:
        parts = cpe_uri.split(":")
        component = parts[index] if len(parts) > index else None
        if component in (None, "-", "*"):
            return None
        return component.replace("\\", "").strip()
    except Exception:  # noqa: BLE001
        return None
