from __future__ import annotations

from datetime import UTC, datetime, timedelta
from functools import lru_cache
from typing import Any

import structlog

from app.services.ingestion.cwe_client import CWEClient
from app.repositories.cwe_repository import CWERepository
from app.models.cwe import CWEEntry

log = structlog.get_logger()


class CWEDescription:
    """Represents a CWE weakness with essential fields for vulnerability analysis."""

    def __init__(self, data: dict[str, Any]) -> None:
        self.id = data.get("ID", "")
        self.name = data.get("Name", "Unknown CWE")
        self.description = data.get("Description", "")
        self.extended_description = data.get("ExtendedDescription", "")
        self.likelihood_of_exploit = data.get("Likelihood_Of_Exploit", "")

        # Extract consequences
        self.consequences: list[str] = []
        common_consequences = data.get("Common_Consequences", {})
        if isinstance(common_consequences, dict):
            consequences_list = common_consequences.get("Consequence", [])
            if not isinstance(consequences_list, list):
                consequences_list = [consequences_list] if consequences_list else []

            for consequence in consequences_list:
                if isinstance(consequence, dict):
                    scope = consequence.get("Scope", [])
                    impact = consequence.get("Impact", [])
                    if scope or impact:
                        scope_str = ", ".join(scope) if isinstance(scope, list) else str(scope)
                        impact_str = ", ".join(impact) if isinstance(impact, list) else str(impact)
                        self.consequences.append(f"{scope_str}: {impact_str}")

        # Extract mitigation strategies
        self.mitigations: list[str] = []
        potential_mitigations = data.get("Potential_Mitigations", {})
        if isinstance(potential_mitigations, dict):
            mitigation_list = potential_mitigations.get("Mitigation", [])
            if not isinstance(mitigation_list, list):
                mitigation_list = [mitigation_list] if mitigation_list else []

            for mitigation in mitigation_list:
                if isinstance(mitigation, dict):
                    description = mitigation.get("Description", "")
                    if description and isinstance(description, str):
                        # Clean up and truncate
                        clean_desc = description.strip()[:200]
                        self.mitigations.append(clean_desc)

    def get_short_description(self) -> str:
        """Get a concise description suitable for inline display."""
        return self.name

    def get_detailed_description(self) -> str:
        """Get a comprehensive description for AI context."""
        parts = [self.name]

        if self.description:
            parts.append(self.description[:300])

        if self.likelihood_of_exploit:
            parts.append(f"Exploit Likelihood: {self.likelihood_of_exploit}")

        if self.consequences:
            consequences_str = "; ".join(self.consequences[:3])
            parts.append(f"Consequences: {consequences_str}")

        if self.mitigations:
            # First mitigation is usually the most important
            parts.append(f"Mitigation: {self.mitigations[0]}")

        return " | ".join(parts)


class CWEService:
    """
    Service for managing CWE (Common Weakness Enumeration) data.

    Provides cached access to CWE descriptions from MITRE's API.
    Uses MongoDB for persistence with in-memory cache for performance.
    """

    def __init__(
        self,
        client: CWEClient | None = None,
        repository: CWERepository | None = None,
    ) -> None:
        """
        Initialize CWE service.

        Args:
            client: Optional CWE client (for testing/DI)
            repository: Optional CWE repository (for testing/DI)
        """
        self._client = client or CWEClient()
        self._repository: CWERepository | None = repository
        self._cache: dict[str, tuple[datetime, CWEDescription]] = {}
        # Cache CWE data for 7 days (CWE content changes only a few times per year)
        self._cache_ttl = timedelta(days=7)

    def _normalize_cwe_id(self, cwe_id: str) -> str:
        """Normalize CWE ID to consistent format (e.g., '79')."""
        return str(cwe_id).upper().replace("CWE-", "").strip()

    def _is_cache_valid(self, cached_at: datetime) -> bool:
        """Check if cached data is still valid."""
        return datetime.now(UTC) - cached_at < self._cache_ttl

    async def get_description(self, cwe_id: str) -> str:
        """
        Get a short description for a CWE ID.

        Args:
            cwe_id: CWE identifier (e.g., "79", "CWE-79")

        Returns:
            Short description (name) of the CWE, or a fallback message.

        Example:
            desc = await service.get_description("79")
            # Returns: "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"
        """
        cwe_data = await self._get_cwe_data(cwe_id)
        if cwe_data:
            return cwe_data.get_short_description()
        return "See CWE database for details"

    async def get_detailed_description(self, cwe_id: str) -> str:
        """
        Get a detailed description for a CWE ID suitable for AI analysis.

        Args:
            cwe_id: CWE identifier (e.g., "79", "CWE-79")

        Returns:
            Detailed description including name, description, consequences, and mitigations.

        Example:
            desc = await service.get_detailed_description("79")
            # Returns comprehensive XSS information
        """
        cwe_data = await self._get_cwe_data(cwe_id)
        if cwe_data:
            return cwe_data.get_detailed_description()
        return f"CWE-{self._normalize_cwe_id(cwe_id)}: Description not available"

    async def get_bulk_descriptions(
        self, cwe_ids: list[str], *, detailed: bool = False
    ) -> dict[str, str]:
        """
        Get descriptions for multiple CWE IDs in one call.

        Args:
            cwe_ids: List of CWE identifiers
            detailed: Whether to return detailed descriptions (default: short)

        Returns:
            Dict mapping normalized CWE IDs to their descriptions.

        Example:
            descs = await service.get_bulk_descriptions(["79", "89", "22"])
            # Returns {"79": "XSS", "89": "SQL Injection", "22": "Path Traversal"}
        """
        results: dict[str, str] = {}

        for cwe_id in cwe_ids:
            normalized_id = self._normalize_cwe_id(cwe_id)
            if detailed:
                results[normalized_id] = await self.get_detailed_description(cwe_id)
            else:
                results[normalized_id] = await self.get_description(cwe_id)

        return results

    async def get_bulk_cwe_data(self, cwe_ids: list[str]) -> dict[str, CWEDescription]:
        """Get CWEDescription objects for multiple CWE IDs."""
        results: dict[str, CWEDescription] = {}
        for cwe_id in cwe_ids:
            normalized_id = self._normalize_cwe_id(cwe_id)
            data = await self._get_cwe_data(cwe_id)
            if data:
                results[normalized_id] = data
        return results

    async def _ensure_repository(self) -> CWERepository:
        """Ensure repository is initialized (lazy loading)."""
        if self._repository is None:
            self._repository = await CWERepository.create()
        return self._repository

    async def _get_cwe_data(self, cwe_id: str) -> CWEDescription | None:
        """
        Internal method to get CWE data with caching.

        Lookup order: In-memory cache -> MongoDB -> MITRE API

        Args:
            cwe_id: CWE identifier

        Returns:
            CWEDescription object or None if not found.
        """
        normalized_id = self._normalize_cwe_id(cwe_id)

        # 1. Check in-memory cache first
        if normalized_id in self._cache:
            cached_at, cached_data = self._cache[normalized_id]
            if self._is_cache_valid(cached_at):
                log.debug("cwe_service.memory_cache_hit", cwe_id=normalized_id)
                return cached_data
            else:
                log.debug("cwe_service.memory_cache_expired", cwe_id=normalized_id)
                del self._cache[normalized_id]

        # 2. Check MongoDB
        try:
            repo = await self._ensure_repository()
            db_entry = await repo.get_by_id(normalized_id)
            if db_entry:
                # Check if DB entry is still fresh (7 days)
                age = datetime.now(UTC) - db_entry.fetched_at
                if age < self._cache_ttl:
                    log.debug("cwe_service.db_cache_hit", cwe_id=normalized_id)
                    # Convert to CWEDescription and cache in memory
                    cwe_desc = CWEDescription(db_entry.raw_data)
                    self._cache[normalized_id] = (db_entry.fetched_at, cwe_desc)
                    return cwe_desc
                else:
                    log.debug("cwe_service.db_cache_expired", cwe_id=normalized_id, age_days=age.days)
        except Exception as exc:
            log.warning("cwe_service.db_lookup_failed", cwe_id=normalized_id, error=str(exc))

        # 3. Fetch from MITRE API
        log.debug("cwe_service.fetching_from_api", cwe_id=normalized_id)
        raw_data = await self._client.fetch_weakness(normalized_id)

        if raw_data:
            cwe_desc = CWEDescription(raw_data)
            now = datetime.now(UTC)

            # Store in memory cache
            self._cache[normalized_id] = (now, cwe_desc)

            # Persist to MongoDB
            try:
                repo = await self._ensure_repository()
                entry = CWEEntry(
                    cwe_id=normalized_id,
                    name=cwe_desc.name,
                    description=cwe_desc.description,
                    extended_description=cwe_desc.extended_description or None,
                    fetched_at=now,
                    raw_data=raw_data,
                )
                await repo.upsert_entry(entry)
                log.info("cwe_service.persisted", cwe_id=normalized_id, name=cwe_desc.name)
            except Exception as exc:
                log.warning("cwe_service.persist_failed", cwe_id=normalized_id, error=str(exc))

            return cwe_desc

        log.warning("cwe_service.not_found", cwe_id=normalized_id)
        return None

    async def sync_all_cwes(self) -> dict[str, int]:
        """
        Sync ALL CWE weaknesses from MITRE API to MongoDB.

        Uses the /cwe/weakness/all endpoint to fetch the complete dataset
        in a single API call, then persists to MongoDB.

        Returns:
            Dict with statistics: {"fetched": N, "inserted": M, "updated": K, "unchanged": L, "failed": O}
        """
        log.info("cwe_service.sync_all_start")

        stats = {
            "fetched": 0,
            "inserted": 0,
            "updated": 0,
            "unchanged": 0,
            "failed": 0,
        }

        try:
            # Fetch all weaknesses from API
            all_weaknesses = await self._client.fetch_all_weaknesses()
            stats["fetched"] = len(all_weaknesses)

            if not all_weaknesses:
                log.warning("cwe_service.sync_all_no_data")
                return stats

            log.info("cwe_service.sync_all_processing", count=stats["fetched"])

            # Process and persist each weakness
            repo = await self._ensure_repository()
            now = datetime.now(UTC)

            for raw_data in all_weaknesses:
                try:
                    cwe_id_raw = raw_data.get("ID", "")
                    if not cwe_id_raw:
                        stats["failed"] += 1
                        continue

                    normalized_id = self._normalize_cwe_id(cwe_id_raw)

                    # Create CWEDescription for validation
                    cwe_desc = CWEDescription(raw_data)

                    # Create entry for persistence
                    entry = CWEEntry(
                        cwe_id=normalized_id,
                        name=cwe_desc.name,
                        description=cwe_desc.description,
                        extended_description=cwe_desc.extended_description or None,
                        fetched_at=now,
                        raw_data=raw_data,
                    )

                    # Upsert to MongoDB
                    action = await repo.upsert_entry(entry)
                    stats[action] += 1

                    # Also update in-memory cache for immediate availability
                    self._cache[normalized_id] = (now, cwe_desc)

                except Exception as exc:
                    log.warning(
                        "cwe_service.sync_all_item_failed",
                        cwe_id=raw_data.get("ID", "unknown"),
                        error=str(exc),
                    )
                    stats["failed"] += 1

            log.info("cwe_service.sync_all_complete", **stats)
            return stats

        except Exception as exc:
            log.error("cwe_service.sync_all_failed", error=str(exc))
            stats["failed"] = -1  # Indicate complete failure
            return stats

    async def prefetch_common_cwes(self) -> dict[str, int]:
        """
        Prefetch the most common CWEs to warm the cache and persist to MongoDB.

        This should be called on application startup or periodically.

        Returns:
            Dict with statistics: {"fetched": N, "from_cache": M, "from_api": K, "failed": L}
        """
        # Top 50 most common CWEs in vulnerability databases
        common_cwes = [
            "79",
            "89",
            "20",
            "200",
            "22",
            "352",
            "434",
            "94",
            "78",
            "77",
            "918",
            "862",
            "863",
            "287",
            "306",
            "125",
            "787",
            "416",
            "476",
            "119",
            "502",
            "611",
            "798",
            "190",
            "327",
            "295",
            "522",
            "269",
            "362",
            "400",
            "312",
            "311",
            "276",
            "732",
            "59",
            "23",
            "601",
            "639",
            "319",
            "326",
            "330",
            "120",
            "121",
            "129",
            "201",
            "203",
            "209",
            "288",
            "297",
            "401",
        ]

        log.info("cwe_service.prefetch_start", count=len(common_cwes))

        stats = {
            "fetched": 0,
            "from_memory_cache": 0,
            "from_db_cache": 0,
            "from_api": 0,
            "failed": 0,
        }

        for cwe_id in common_cwes:
            normalized_id = self._normalize_cwe_id(cwe_id)

            try:
                # Track where data came from
                was_in_memory = normalized_id in self._cache
                if was_in_memory:
                    cached_at, _ = self._cache[normalized_id]
                    was_in_memory = self._is_cache_valid(cached_at)

                # Get the data (will use cache or fetch)
                data = await self._get_cwe_data(cwe_id)

                if data:
                    stats["fetched"] += 1

                    # Determine source
                    if was_in_memory:
                        stats["from_memory_cache"] += 1
                    else:
                        # Check if it came from DB or API by checking if it was just added to memory cache
                        # If it wasn't in memory but now is, it either came from DB or API
                        # We can check the repository to see if it existed
                        try:
                            repo = await self._ensure_repository()
                            db_entry = await repo.get_by_id(normalized_id)
                            if db_entry and (datetime.now(UTC) - db_entry.fetched_at).total_seconds() > 2:
                                # Existed in DB and wasn't just created (> 2 seconds old)
                                stats["from_db_cache"] += 1
                            else:
                                # Newly fetched from API
                                stats["from_api"] += 1
                        except Exception:
                            # If we can't determine, assume API
                            stats["from_api"] += 1
                else:
                    stats["failed"] += 1
            except Exception as exc:  # pragma: no cover - continue on errors
                log.warning("cwe_service.prefetch_error", cwe_id=cwe_id, error=str(exc))
                stats["failed"] += 1
                continue

        log.info("cwe_service.prefetch_complete", **stats, total=len(common_cwes))
        return stats

    def clear_cache(self) -> None:
        """Clear the in-memory CWE cache."""
        count = len(self._cache)
        self._cache.clear()
        log.info("cwe_service.memory_cache_cleared", count=count)

    async def clear_old_entries(self) -> int:
        """
        Delete CWE entries from MongoDB that are older than the cache TTL.

        Returns:
            Number of entries deleted
        """
        try:
            repo = await self._ensure_repository()
            cutoff = datetime.now(UTC) - self._cache_ttl
            deleted = await repo.delete_old_entries(cutoff)
            log.info("cwe_service.old_entries_deleted", count=deleted, cutoff=cutoff)
            return deleted
        except Exception as exc:
            log.warning("cwe_service.cleanup_failed", error=str(exc))
            return 0

    async def close(self) -> None:
        """Close the underlying CWE client."""
        if self._client:
            await self._client.close()


@lru_cache(maxsize=1)
def get_cwe_service() -> CWEService:
    """Get singleton CWE service instance."""
    return CWEService()
