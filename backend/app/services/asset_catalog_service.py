from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable
import re

import structlog

from app.repositories.asset_repository import AssetRepository
from app.repositories.vulnerability_repository import VulnerabilityRepository
from app.utils.strings import normalize_key

log = structlog.get_logger()


@dataclass(slots=True)
class AssetCatalogResult:
    vendor_slugs: list[str]
    product_slugs: list[str]
    version_strings: list[str]
    version_ids: list[str]


@dataclass(slots=True)
class ParsedCPE:
    vendor: str | None
    product: str | None
    version: str | None


class AssetCatalogService:
    """
    Maintains a vendor/product/version catalog derived from EUVD records.
    """

    def __init__(self, repository: AssetRepository) -> None:
        self.repository = repository

    @classmethod
    async def create(cls) -> "AssetCatalogService":
        repository = await AssetRepository.create()
        return cls(repository)

    async def record_assets(
        self,
        *,
        vendors: list[str],
        product_versions: dict[str, set[str]],
        cpes: Iterable[str],
        cpe_configurations: Iterable[dict[str, Any]] | None = None,
    ) -> AssetCatalogResult:
        parsed_cpes = [entry for entry in (self._parse_cpe_uri(cpe) for cpe in cpes) if entry]
        vendor_slugs: list[str] = []
        vendor_key_map: dict[str, str] = {}
        sources = {"EUVD"}

        product_token_map = self._build_product_token_map(cpe_configurations)
        if product_token_map:
            for product_key, entry in product_token_map.items():
                label = entry.get("label") or product_key
                tokens = entry.get("tokens") or set()
                if not tokens:
                    continue
                target_label = next(
                    (name for name in product_versions if normalize_key(name) == product_key),
                    label,
                )
                bucket = product_versions.setdefault(target_label, set())
                bucket.update(tokens)

        for vendor in vendors:
            alias_candidates = self._matching_cpe_vendors(vendor, parsed_cpes)
            try:
                slug = await self.repository.upsert_vendor(vendor, aliases=alias_candidates, sources=sources)
            except RuntimeError as exc:
                log.warning("asset_catalog.vendor_upsert_failed", vendor=vendor, error=str(exc))
                continue
            vendor_slugs.append(slug)
            vendor_key_map[normalize_key(vendor)] = slug

        product_slugs: list[str] = []
        all_versions: set[str] = set()
        all_version_ids: set[str] = set()

        for product_name, versions in product_versions.items():
            alias_candidates = self._matching_cpe_products(product_name, parsed_cpes)
            cpe_names = [candidate.replace(":", " ").replace("_", " ") for candidate in alias_candidates if candidate]
            try:
                product_slug = await self.repository.upsert_product(
                    product_name,
                    vendor_slugs=vendor_slugs or vendor_key_map.values(),
                    aliases={candidate.replace("_", " ") for candidate in alias_candidates},
                    cpe_names=alias_candidates,
                    sources=sources,
                )
            except RuntimeError as exc:
                log.warning("asset_catalog.product_upsert_failed", product=product_name, error=str(exc))
                continue

            product_slugs.append(product_slug)

            combined_versions = {value for value in versions if value}
            combined_versions |= {entry.version for entry in parsed_cpes if entry.version and self._matches_product(entry.product, product_name)}

            filtered_versions = {version for version in (combined_versions or set()) if version and version not in {"*", "-"}}

            try:
                version_ids = await self.repository.upsert_versions(
                    product_slug,
                    versions=filtered_versions,
                    sources=sources,
                )
            except RuntimeError as exc:
                log.warning("asset_catalog.version_upsert_failed", product=product_name, error=str(exc))
                continue

            all_versions.update(filtered_versions)
            all_version_ids.update(version_ids)

        return AssetCatalogResult(
            vendor_slugs=sorted(set(vendor_slugs)),
            product_slugs=sorted(set(product_slugs)),
            version_strings=sorted(all_versions),
            version_ids=sorted(all_version_ids),
        )

    async def search_vendors(self, keyword: str | None, *, limit: int, offset: int) -> tuple[int, list[dict[str, Any]]]:
        total, documents = await self.repository.search_vendors(keyword, limit=limit, offset=offset)
        return total, [self._serialize_vendor(document) for document in documents]

    async def search_products(
        self,
        *,
        vendor_slugs: Iterable[str] | None,
        keyword: str | None,
        limit: int,
        offset: int,
    ) -> tuple[int, list[dict[str, Any]]]:
        total, documents = await self.repository.search_products(
            vendor_slugs=vendor_slugs,
            keyword=keyword,
            limit=limit,
            offset=offset,
        )
        if vendor_slugs and not documents:
            await self._hydrate_products_from_vulnerabilities(vendor_slugs)
            total, documents = await self.repository.search_products(
                vendor_slugs=vendor_slugs,
                keyword=keyword,
                limit=limit,
                offset=offset,
            )
        return total, [self._serialize_product(document) for document in documents]

    async def list_versions(
        self,
        *,
        product_slug: str,
        keyword: str | None,
        limit: int,
        offset: int,
    ) -> tuple[int, list[dict[str, Any]]]:
        total, documents = await self.repository.list_versions(
            product_slug=product_slug,
            keyword=keyword,
            limit=limit,
            offset=offset,
        )
        return total, [self._serialize_version(document) for document in documents]

    @staticmethod
    def _parse_cpe_uri(value: str | None) -> ParsedCPE | None:
        if not value or not isinstance(value, str):
            return None
        parts = value.split(":")
        if len(parts) < 6:
            return None

        vendor = AssetCatalogService._clean_cpe_component(parts[3])
        product = AssetCatalogService._clean_cpe_component(parts[4])
        version = AssetCatalogService._clean_cpe_component(parts[5])
        return ParsedCPE(vendor=vendor, product=product, version=version)

    @staticmethod
    def _clean_cpe_component(value: str | None) -> str | None:
        if not value:
            return None
        value = value.replace("\\", "").strip()
        if value in {"*", "-"}:
            return None
        return value

    @staticmethod
    def _matches_product(candidate: str | None, product_name: str) -> bool:
        if not candidate:
            return False
        return normalize_key(candidate) == normalize_key(product_name)

    @staticmethod
    def _sanitize_version_token(value: Any) -> str | None:
        if not isinstance(value, str):
            return None
        normalized = value.strip()
        if not normalized:
            return None
        normalized = normalized.replace("*", "x")
        normalized = normalized.replace("_", ".").replace("-", ".")
        normalized = re.sub(r"\s+", "", normalized)
        if not re.fullmatch(r"[0-9xX]+(?:\.[0-9xX]+){0,5}", normalized):
            return None
        return normalized.lower()

    @staticmethod
    def _build_product_token_map(
        cpe_configurations: Iterable[dict[str, Any]] | None,
    ) -> dict[str, dict[str, Any]]:
        product_map: dict[str, dict[str, Any]] = {}
        if not cpe_configurations:
            return {}
        for configuration in cpe_configurations:
            if not isinstance(configuration, dict):
                continue
            nodes = configuration.get("nodes")
            if isinstance(nodes, list):
                for node in nodes:
                    AssetCatalogService._collect_tokens_from_node(node, product_map)
        return {key: entry for key, entry in product_map.items() if entry.get("tokens")}

    @staticmethod
    def _collect_tokens_from_node(node: Any, product_map: dict[str, dict[str, Any]]) -> None:
        if not isinstance(node, dict):
            return

        matches = node.get("matches")
        if isinstance(matches, list):
            for match in matches:
                if not isinstance(match, dict):
                    continue
                product_label = match.get("product") or match.get("productRaw")
                if not isinstance(product_label, str) or not product_label.strip():
                    continue
                normalized_key = normalize_key(product_label)
                entry = product_map.setdefault(
                    normalized_key,
                    {"label": product_label.strip(), "tokens": set()},
                )
                for field in (
                    "version",
                    "versionStartIncluding",
                    "versionStartExcluding",
                    "versionEndIncluding",
                    "versionEndExcluding",
                ):
                    candidate = AssetCatalogService._sanitize_version_token(match.get(field))
                    if candidate:
                        entry["tokens"].add(candidate)
                token_values = match.get("versionTokens")
                if isinstance(token_values, list):
                    for token in token_values:
                        candidate = AssetCatalogService._sanitize_version_token(token)
                        if candidate:
                            entry["tokens"].add(candidate)

        child_nodes = node.get("nodes")
        if isinstance(child_nodes, list):
            for child in child_nodes:
                AssetCatalogService._collect_tokens_from_node(child, product_map)

    def _matching_cpe_vendors(self, vendor: str, cpe_entries: list[ParsedCPE]) -> set[str]:
        key = normalize_key(vendor)
        matches = {vendor}
        for entry in cpe_entries:
            if entry.vendor and normalize_key(entry.vendor) == key:
                matches.add(entry.vendor.replace("_", " "))
        return matches

    def _matching_cpe_products(self, product: str, cpe_entries: list[ParsedCPE]) -> set[str]:
        key = normalize_key(product)
        matches: set[str] = {product}
        for entry in cpe_entries:
            if entry.product and normalize_key(entry.product) == key:
                matches.add(entry.product)
        return matches

    @staticmethod
    def _serialize_vendor(document: dict[str, Any]) -> dict[str, Any]:
        return {
            "slug": document.get("_id"),
            "name": document.get("displayName") or document.get("_id"),
            "aliases": sorted({alias for alias in document.get("aliases", []) if alias}),
        }

    @staticmethod
    def _serialize_product(document: dict[str, Any]) -> dict[str, Any]:
        return {
            "slug": document.get("_id"),
            "name": document.get("displayName") or document.get("_id"),
            "aliases": sorted({alias for alias in document.get("aliases", []) if alias}),
            "vendorSlugs": sorted({slug for slug in document.get("vendorSlugs", []) if slug}),
        }

    @staticmethod
    def _serialize_version(document: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": document.get("_id"),
            "value": document.get("displayName") or document.get("_id"),
            "productSlug": document.get("productSlug"),
        }
    async def _hydrate_products_from_vulnerabilities(self, vendor_slugs: Iterable[str]) -> None:
        normalized_slugs = [slug for slug in vendor_slugs if slug]
        if not normalized_slugs:
            return

        vendor_docs = await self.repository.find_vendors_by_slugs(normalized_slugs)
        if not vendor_docs:
            return

        vendor_aliases: set[str] = set()
        for doc in vendor_docs:
            display = doc.get("displayName")
            if isinstance(display, str) and display:
                vendor_aliases.add(display)
            for alias in doc.get("aliases", []) or []:
                if isinstance(alias, str) and alias:
                    vendor_aliases.add(alias)

        if not vendor_aliases:
            return

        vulnerability_repo = await VulnerabilityRepository.create()
        pipeline: list[dict[str, Any]] = [
            {"$match": {"vendors": {"$in": sorted(vendor_aliases)}}},
            {"$unwind": "$products"},
            {"$match": {"products": {"$nin": [None, "", "*"]}}},
            {"$group": {"_id": "$products", "count": {"$sum": 1}}},
            {"$sort": {"count": -1, "_id": 1}},
            {"$limit": 100},
        ]

        products = await vulnerability_repo.collection.aggregate(pipeline).to_list(length=100)
        for product in products:
            name = product.get("_id")
            if not isinstance(name, str) or not name.strip():
                continue
            try:
                await self.repository.upsert_product(
                    name,
                    vendor_slugs=normalized_slugs,
                    aliases={name},
                    sources={"VULNERABILITY_FALLBACK"},
                )
            except RuntimeError:
                continue


async def get_asset_catalog_service() -> AssetCatalogService:
    return await AssetCatalogService.create()
