from __future__ import annotations

from datetime import UTC, datetime, timedelta
from functools import lru_cache
from typing import Any

import structlog

from app.models.capec import CAPECEntry
from app.repositories.capec_repository import CAPECRepository
from app.services.ingestion.capec_client import CAPECClient

log = structlog.get_logger()


_SEVERITY_ORDER = {"very high": 0, "high": 1, "medium": 2, "low": 3, "": 4}


class CAPECDescription:
    """Represents a CAPEC attack pattern with essential fields."""

    def __init__(self, data: dict[str, Any]) -> None:
        self.id = data.get("ID", "")
        self.name = data.get("Name", "Unknown CAPEC")
        self.description = data.get("Description", "")
        self.severity = data.get("Typical_Severity", "")
        self.likelihood = data.get("Likelihood_Of_Attack", "")
        self.abstraction = data.get("Abstraction", "")
        self.related_cwes: list[str] = data.get("Related_Weaknesses", [])

    def get_short_description(self) -> str:
        return self.name

    def get_detailed_description(self) -> str:
        parts = [self.name]

        if self.description:
            parts.append(self.description[:300])

        if self.severity:
            parts.append(f"Severity: {self.severity}")

        if self.likelihood:
            parts.append(f"Likelihood: {self.likelihood}")

        return " | ".join(parts)


class CAPECService:
    """
    Service for managing CAPEC (Common Attack Pattern Enumeration and Classification) data.

    Provides cached access to CAPEC descriptions from MITRE's XML feed.
    Uses MongoDB for persistence with in-memory cache for performance.
    Also resolves CWE IDs to related CAPEC attack patterns.
    """

    def __init__(
        self,
        client: CAPECClient | None = None,
        repository: CAPECRepository | None = None,
    ) -> None:
        self._client = client or CAPECClient()
        self._repository: CAPECRepository | None = repository
        self._cache: dict[str, tuple[datetime, CAPECDescription]] = {}
        self._cache_ttl = timedelta(days=7)
        # Emit "catalog is stale" exactly once per process so admins notice
        # without flooding logs on every read.
        self._stale_warning_emitted: bool = False
        # CWE→CAPEC mapping: built from CWE raw data's RelatedAttackPatterns
        # and from CAPEC raw data's Related_Weaknesses
        self._cwe_to_capec: dict[str, set[str]] = {}
        self._cwe_mapping_loaded = False

    def _normalize_capec_id(self, capec_id: str) -> str:
        return str(capec_id).upper().replace("CAPEC-", "").strip()

    def _is_cache_valid(self, cached_at: datetime) -> bool:
        return datetime.now(UTC) - cached_at < self._cache_ttl

    async def get_description(self, capec_id: str) -> str:
        capec_data = await self._get_capec_data(capec_id)
        if capec_data:
            return capec_data.get_short_description()
        return "See CAPEC database for details"

    async def get_bulk_descriptions(
        self, capec_ids: list[str], *, detailed: bool = False
    ) -> dict[str, str]:
        results: dict[str, str] = {}

        for capec_id in capec_ids:
            normalized_id = self._normalize_capec_id(capec_id)
            capec_data = await self._get_capec_data(capec_id)
            if capec_data:
                if detailed:
                    results[normalized_id] = capec_data.get_detailed_description()
                else:
                    results[normalized_id] = capec_data.get_short_description()
            else:
                results[normalized_id] = "See CAPEC database for details"

        return results

    async def get_capecs_for_cwes(self, cwe_ids: list[str]) -> dict[str, CAPECDescription]:
        """
        Resolve CWE IDs to their related CAPEC attack patterns.

        Uses the CWE→CAPEC mapping built from:
        1. CWE raw data's ``RelatedAttackPatterns`` field (stored during CWE sync)
        2. CAPEC raw data's ``Related_Weaknesses`` field (stored during CAPEC sync)

        Filters out "Meta" abstraction patterns (too broad), removes parent CWEs
        when more specific children are present, and sorts by severity.

        Returns:
            Dict mapping normalized CAPEC IDs to CAPECDescription objects.
        """
        await self._ensure_cwe_mapping()

        normalized_cwes = {
            cwe_id.upper().replace("CWE-", "").strip() for cwe_id in cwe_ids
        }

        # Remove parent CWEs when their children are also in the list.
        # E.g. CWE-74 (Injection) is a parent of CWE-77 (Command Injection).
        # Including the parent would flood results with unrelated attack patterns.
        effective_cwes = await self._remove_parent_cwes(normalized_cwes)

        # Collect unique CAPEC IDs for the effective CWEs
        capec_ids: set[str] = set()
        for cwe_id in effective_cwes:
            related = self._cwe_to_capec.get(cwe_id, set())
            capec_ids.update(related)

        if not capec_ids:
            return {}

        # Fetch CAPEC details, filtering out Meta-level patterns
        items: list[tuple[str, CAPECDescription]] = []
        for capec_id in capec_ids:
            capec_data = await self._get_capec_data(capec_id)
            if capec_data and capec_data.abstraction != "Meta":
                items.append((capec_id, capec_data))

        # Sort by severity (High first), then by ID for stability
        items.sort(key=lambda item: (
            _SEVERITY_ORDER.get(item[1].severity.lower(), 3),
            int(item[0]) if item[0].isdigit() else 9999,
        ))

        return dict(items)

    async def _remove_parent_cwes(self, cwe_ids: set[str]) -> set[str]:
        """
        Given a set of CWE IDs, remove any that are parents of other CWEs
        in the same set. Uses CWE RelatedWeaknesses (ChildOf) from MongoDB.

        Example: {74, 77} → {77}, because CWE-77 is ChildOf CWE-74.
        """
        if len(cwe_ids) <= 1:
            return cwe_ids

        # Build set of parent IDs by checking each CWE's RelatedWeaknesses
        parent_ids: set[str] = set()
        try:
            from app.repositories.cwe_repository import CWERepository

            cwe_repo = await CWERepository.create()
            for cwe_id in cwe_ids:
                entry = await cwe_repo.get_by_id(cwe_id)
                if not entry:
                    continue
                related = entry.raw_data.get("RelatedWeaknesses", [])
                if not isinstance(related, list):
                    continue
                for rel in related:
                    if isinstance(rel, dict) and rel.get("Nature") == "ChildOf":
                        parent_cwe = str(rel.get("CweID", "")).strip()
                        if parent_cwe in cwe_ids:
                            parent_ids.add(parent_cwe)
        except Exception as exc:
            log.warning("capec_service.parent_cwe_check_failed", error=str(exc))
            return cwe_ids

        if parent_ids:
            log.info(
                "capec_service.removed_parent_cwes",
                original=sorted(cwe_ids),
                removed=sorted(parent_ids),
            )

        return cwe_ids - parent_ids

    async def _ensure_cwe_mapping(self) -> None:
        """Build the CWE→CAPEC mapping if not already loaded."""
        if self._cwe_mapping_loaded:
            return

        # Strategy 1: Build from CAPEC data (Related_Weaknesses in each CAPEC entry)
        try:
            repo = await self._ensure_repository()
            cursor = repo.collection.find({}, {"capec_id": 1, "raw_data": 1})
            async for document in cursor:
                capec_id = document.get("capec_id", "")
                raw_data = document.get("raw_data", {})
                if not capec_id or not isinstance(raw_data, dict):
                    continue

                related_cwes = raw_data.get("Related_Weaknesses", [])
                if isinstance(related_cwes, list):
                    for cwe_id in related_cwes:
                        normalized_cwe = str(cwe_id).upper().replace("CWE-", "").strip()
                        if normalized_cwe:
                            self._cwe_to_capec.setdefault(normalized_cwe, set()).add(capec_id)
        except Exception as exc:
            log.warning("capec_service.cwe_mapping_from_capec_failed", error=str(exc))

        # Strategy 2: Supplement from CWE raw data (RelatedAttackPatterns field)
        try:
            from app.repositories.cwe_repository import CWERepository

            cwe_repo = await CWERepository.create()
            cursor = cwe_repo.collection.find({}, {"cwe_id": 1, "raw_data": 1})
            async for document in cursor:
                cwe_id = document.get("cwe_id", "")
                raw_data = document.get("raw_data", {})
                if not cwe_id or not isinstance(raw_data, dict):
                    continue

                related_patterns = raw_data.get("RelatedAttackPatterns", [])
                if isinstance(related_patterns, list):
                    for capec_id in related_patterns:
                        normalized_capec = str(capec_id).strip()
                        if normalized_capec:
                            self._cwe_to_capec.setdefault(cwe_id, set()).add(normalized_capec)
        except Exception as exc:
            log.warning("capec_service.cwe_mapping_from_cwe_failed", error=str(exc))

        self._cwe_mapping_loaded = True
        total_mappings = sum(len(v) for v in self._cwe_to_capec.values())
        log.info(
            "capec_service.cwe_mapping_loaded",
            cwe_count=len(self._cwe_to_capec),
            total_mappings=total_mappings,
        )

    async def _ensure_repository(self) -> CAPECRepository:
        if self._repository is None:
            self._repository = await CAPECRepository.create()
        return self._repository

    async def _get_capec_data(self, capec_id: str) -> CAPECDescription | None:
        normalized_id = self._normalize_capec_id(capec_id)

        # 1. In-memory cache (only honors fresh TTL — stale entries fall through to Mongo)
        if normalized_id in self._cache:
            cached_at, cached_data = self._cache[normalized_id]
            if self._is_cache_valid(cached_at):
                return cached_data
            else:
                del self._cache[normalized_id]

        # 2. MongoDB. CAPEC content changes a few times per year and the only
        #    refresh source is the bulk XML feed (no per-ID API). Serve whatever
        #    is on disk and emit a single warning per process when the catalog
        #    has drifted past the TTL — better than dropping the whole CAPEC
        #    layer when the scheduler has been blocked from running.
        try:
            repo = await self._ensure_repository()
            db_entry = await repo.get_by_id(normalized_id)
            if db_entry:
                age = datetime.now(UTC) - db_entry.fetched_at
                if age >= self._cache_ttl and not self._stale_warning_emitted:
                    log.warning(
                        "capec_service.catalog_stale",
                        oldest_fetched_at=db_entry.fetched_at.isoformat(),
                        age_days=age.days,
                        ttl_days=self._cache_ttl.days,
                        hint="Run `python -m app.cli sync-capec --initial` or wait for the scheduler.",
                    )
                    self._stale_warning_emitted = True
                capec_desc = CAPECDescription(db_entry.raw_data)
                self._cache[normalized_id] = (db_entry.fetched_at, capec_desc)
                return capec_desc
        except Exception as exc:
            log.warning("capec_service.db_lookup_failed", capec_id=normalized_id, error=str(exc))

        # 3. No REST API fallback - CAPEC data must be synced via XML first
        log.debug("capec_service.not_found", capec_id=normalized_id)
        return None

    async def sync_all_capecs(self) -> dict[str, int]:
        """
        Sync ALL CAPEC attack patterns from MITRE XML to MongoDB.

        Returns:
            Dict with statistics: {"fetched": N, "inserted": M, "updated": K, "unchanged": L, "failed": O}
        """
        log.info("capec_service.sync_all_start")

        stats = {
            "fetched": 0,
            "inserted": 0,
            "updated": 0,
            "unchanged": 0,
            "failed": 0,
        }

        try:
            all_patterns = await self._client.fetch_all_attack_patterns()
            stats["fetched"] = len(all_patterns)

            if not all_patterns:
                log.warning("capec_service.sync_all_no_data")
                return stats

            log.info("capec_service.sync_all_processing", count=stats["fetched"])

            repo = await self._ensure_repository()
            now = datetime.now(UTC)

            for raw_data in all_patterns:
                try:
                    capec_id_raw = raw_data.get("ID", "")
                    if not capec_id_raw:
                        stats["failed"] += 1
                        continue

                    normalized_id = self._normalize_capec_id(capec_id_raw)
                    capec_desc = CAPECDescription(raw_data)

                    entry = CAPECEntry(
                        capec_id=normalized_id,
                        name=capec_desc.name,
                        description=capec_desc.description,
                        fetched_at=now,
                        raw_data=raw_data,
                    )

                    action = await repo.upsert_entry(entry)
                    stats[action] += 1

                    self._cache[normalized_id] = (now, capec_desc)

                except Exception as exc:
                    log.warning(
                        "capec_service.sync_all_item_failed",
                        capec_id=raw_data.get("ID", "unknown"),
                        error=str(exc),
                    )
                    stats["failed"] += 1

            # Reset CWE mapping so it gets rebuilt with fresh data
            self._cwe_mapping_loaded = False
            self._cwe_to_capec.clear()

            log.info("capec_service.sync_all_complete", **stats)
            return stats

        except Exception as exc:
            log.error("capec_service.sync_all_failed", error=str(exc))
            stats["failed"] = -1
            return stats

    def clear_cache(self) -> None:
        count = len(self._cache)
        self._cache.clear()
        self._cwe_to_capec.clear()
        self._cwe_mapping_loaded = False
        log.info("capec_service.memory_cache_cleared", count=count)

    async def clear_old_entries(self) -> int:
        try:
            repo = await self._ensure_repository()
            cutoff = datetime.now(UTC) - self._cache_ttl
            deleted = await repo.delete_old_entries(cutoff)
            log.info("capec_service.old_entries_deleted", count=deleted, cutoff=cutoff)
            return deleted
        except Exception as exc:
            log.warning("capec_service.cleanup_failed", error=str(exc))
            return 0

    async def close(self) -> None:
        if self._client:
            await self._client.close()


@lru_cache(maxsize=1)
def get_capec_service() -> CAPECService:
    """Get singleton CAPEC service instance."""
    return CAPECService()
