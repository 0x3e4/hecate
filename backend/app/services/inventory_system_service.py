"""Systems in the inventory and their link to pushed SBOMs and scanner reports.

A system (a server, VM, Kubernetes node) is listed once, by name. What is
installed on it arrives as an SBOM or scanner report through the SBOM import
and lands on an SBOM-import scan target; the system points at that target
(``target_id``) and reads its last report, findings and history from it.

Linking happens on every import (``link_import``):

1. a system already linked to the target stays linked;
2. otherwise a system of the same name (case-insensitive) is linked, so a
   system entered by hand or from a server list picks up its first push;
3. otherwise, when the import says what the target is (``kind``), a system
   is created for it. An SBOM without ``kind`` (an application, a vendor's
   product) stays a plain SCA target.

``kind`` and ``exposure`` are kept on both the system and the target: the
target's copy feeds "Affected in your scans" (internet-facing first). Every
change on one side is written to the other (``set_classification`` here,
``mirror_target_classification`` for edits made on the target).
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import structlog

from app.core.config import settings
from app.repositories.inventory_repository import InventoryRepository
from app.repositories.inventory_system_repository import InventorySystemRepository, SystemNameTaken, name_key
from app.repositories.scan_target_repository import ScanTargetRepository
from app.schemas.inventory_system import (
    InventorySystemCreateRequest,
    InventorySystemImportResponse,
    InventorySystemListResponse,
    InventorySystemResponse,
    InventorySystemUpdateRequest,
)

from app.services.inventory_system_lists import ParsedList

log = structlog.get_logger()


class ListTooDestructive(ValueError):
    """A replace would retire more than half of the systems its source named."""

    def __init__(self, retiring: int, named: int) -> None:
        super().__init__(
            f"This list would retire {retiring} of the {named} systems it named before. "
            "Check the list, or send force=true if that is right."
        )
        self.retiring = retiring
        self.named = named


_CLEARABLE = ("kind", "exposure", "environment", "owner", "notes")


def report_status(last_report_at: datetime | None, now: datetime, stale_after_days: int) -> str:
    """``reporting`` / ``stale`` / ``never`` for the time the last report arrived."""
    if last_report_at is None:
        return "never"
    if last_report_at.tzinfo is None:
        last_report_at = last_report_at.replace(tzinfo=UTC)
    return "reporting" if now - last_report_at <= timedelta(days=stale_after_days) else "stale"


def _text(value: str | None) -> str | None:
    value = (value or "").strip()
    return value or None


class InventorySystemService:
    def __init__(
        self,
        repo: InventorySystemRepository | None = None,
        target_repo: ScanTargetRepository | None = None,
        item_repo: InventoryRepository | None = None,
    ) -> None:
        self._repo = repo
        self._target_repo = target_repo
        self._item_repo = item_repo

    async def repo(self) -> InventorySystemRepository:
        if self._repo is None:
            self._repo = await InventorySystemRepository.create()
        return self._repo

    async def target_repo(self) -> ScanTargetRepository:
        if self._target_repo is None:
            self._target_repo = await ScanTargetRepository.create()
        return self._target_repo

    async def item_repo(self) -> InventoryRepository:
        if self._item_repo is None:
            self._item_repo = await InventoryRepository.create()
        return self._item_repo

    # ---------------------------------------------------------------- reads

    async def _responses(self, docs: list[dict[str, Any]]) -> list[InventorySystemResponse]:
        target_ids = [d["target_id"] for d in docs if isinstance(d.get("target_id"), str)]
        targets: dict[str, dict[str, Any]] = {}
        if target_ids:
            collection = (await self.target_repo()).collection
            projection = {"last_scan_at": 1, "latest_scan_id": 1, "latest_summary": 1}
            async for doc in collection.find({"_id": {"$in": target_ids}}, projection=projection):
                targets[str(doc["_id"])] = doc
        products: dict[str, list[dict[str, str]]] = {}
        ids = [str(d["_id"]) for d in docs]
        if ids:
            items = (await self.item_repo()).collection
            async for item in items.find({"system_ids": {"$in": ids}}, projection={"name": 1, "version": 1, "system_ids": 1}):
                for system_id in item.get("system_ids") or []:
                    products.setdefault(system_id, []).append(
                        {"id": str(item["_id"]), "name": item.get("name", ""), "version": item.get("version", "")}
                    )
        now = datetime.now(tz=UTC)
        out = []
        for doc in docs:
            target = targets.get(doc.get("target_id") or "") or {}
            last = target.get("last_scan_at")
            out.append(InventorySystemResponse.model_validate({
                "id": str(doc["_id"]),
                "name": doc.get("name", ""),
                "kind": doc.get("kind"),
                "exposure": doc.get("exposure"),
                "environment": doc.get("environment"),
                "owner": doc.get("owner"),
                "notes": doc.get("notes"),
                "groups": doc.get("groups") or [],
                "source": doc.get("source") or "manual",
                # A link to a deleted target reads as no link.
                "targetId": doc.get("target_id") if target else None,
                "lastReportAt": last,
                "reportStatus": report_status(last if target else None, now, settings.inventory_system_stale_days),
                "latestScanId": target.get("latest_scan_id"),
                "latestSummary": target.get("latest_summary"),
                "products": sorted(products.get(str(doc["_id"]), []), key=lambda p: p["name"].casefold()),
                "listSources": doc.get("list_sources") or [],
                "retiredAt": doc.get("retired_at"),
                "createdAt": doc.get("created_at"),
                "updatedAt": doc.get("updated_at"),
            }))
        return out

    async def list_systems(self) -> InventorySystemListResponse:
        docs = await (await self.repo()).list_all()
        items = await self._responses(docs)
        return InventorySystemListResponse(total=len(items), stale_after_days=settings.inventory_system_stale_days, items=items)

    async def get_system(self, system_id: str) -> InventorySystemResponse | None:
        doc = await (await self.repo()).get(system_id)
        return (await self._responses([doc]))[0] if doc else None

    async def system_ids(self) -> set[str]:
        return {str(d["_id"]) for d in await (await self.repo()).list_all()}

    async def find_system(self, ref: str) -> dict[str, Any] | None:
        """The system with this id, else with this name (case-insensitive)."""
        ref = (ref or "").strip()
        if not ref:
            return None
        repo = await self.repo()
        return await repo.get(ref) or await repo.get_by_name(ref)

    async def resolve_refs(self, refs: list[str]) -> tuple[list[str], list[str]]:
        """Ids for system ids or names, in order without repeats, and the refs that matched nothing."""
        ids: list[str] = []
        unknown: list[str] = []
        for ref in refs:
            doc = await self.find_system(ref)
            if doc is None:
                unknown.append(ref)
            elif str(doc["_id"]) not in ids:
                ids.append(str(doc["_id"]))
        return ids, unknown

    # ---------------------------------------------------------------- writes

    async def create_system(self, payload: InventorySystemCreateRequest) -> InventorySystemResponse:
        """A new system; ``SystemNameTaken`` when the name is in use. A target of the same name is linked."""
        repo = await self.repo()
        data: dict[str, Any] = {
            "name": payload.name,
            "groups": payload.groups,
            "source": "manual",
            **{k: v for k, v in (
                ("kind", payload.kind), ("exposure", payload.exposure), ("environment", _text(payload.environment)),
                ("owner", _text(payload.owner)), ("notes", _text(payload.notes)),
            ) if v},
        }
        system_id = str(uuid4())
        await repo.insert(system_id, data)
        await self._link_existing_target(system_id, payload.name)
        return await self.get_system(system_id)  # type: ignore[return-value]

    async def _link_existing_target(self, system_id: str, name: str) -> None:
        """A system entered by hand takes over an SBOM-import target of its name that no system holds yet."""
        from app.services.scan_service import sbom_import_target_id

        try:
            targets = await self.target_repo()
            doc = await targets.collection.find_one(
                {"type": "sbom-import", "$or": [{"_id": sbom_import_target_id(name)}, {"name": name}]},
            )
            if not doc:
                return
            target = {**doc, "target_id": str(doc["_id"])}
            repo = await self.repo()
            if await repo.get_by_target(target["target_id"]):
                return
            await repo.update(system_id, {"target_id": target["target_id"]})
            system = await repo.get(system_id) or {}
            await self._sync_target_classification(target["target_id"], system, target)
        except Exception:  # noqa: BLE001 - the system exists either way
            log.warning("inventory_system.link_existing_failed", system_id=system_id, exc_info=True)

    async def update_system(self, system_id: str, payload: InventorySystemUpdateRequest) -> InventorySystemResponse | None:
        repo = await self.repo()
        existing = await repo.get(system_id)
        if existing is None:
            return None
        given = payload.model_fields_set
        set_fields: dict[str, Any] = {}
        unset: list[str] = []
        if "name" in given and payload.name:
            set_fields["name"] = payload.name
        if "groups" in given and payload.groups is not None:
            set_fields["groups"] = payload.groups
        for field in _CLEARABLE:
            if field not in given:
                continue
            value = getattr(payload, field)
            value = _text(value) if field in ("environment", "owner", "notes") else value
            if value is None:
                unset.append(field)
            else:
                set_fields[field] = value
        await repo.update(system_id, set_fields, unset)
        classification = {k: getattr(payload, k) for k in ("kind", "exposure") if k in given}
        if classification and isinstance(existing.get("target_id"), str):
            await (await self.target_repo()).update_classification(existing["target_id"], classification)
        return await self.get_system(system_id)

    async def delete_system(self, system_id: str) -> bool:
        """Remove the system and its product links; its target and scan history stay (an SCA target again)."""
        deleted = await (await self.repo()).delete(system_id)
        if deleted:
            await (await self.item_repo()).collection.update_many(
                {"system_ids": system_id}, {"$pull": {"system_ids": system_id}},
            )
        return deleted

    # ---------------------------------------------------------------- the import side

    async def link_import(
        self, target_id: str, target_name: str, kind: str | None, exposure: str | None,
    ) -> str | None:
        """Link (or create) the system an import belongs to; its id, or ``None``. Never raises."""
        try:
            repo = await self.repo()
            system = await repo.get_by_target(target_id)
            if system is not None:
                fields = {k: v for k, v in (("kind", kind), ("exposure", exposure)) if v}
                # A push from a retired system brings it back: it is evidently running.
                if fields or system.get("retired_at"):
                    await repo.update(str(system["_id"]), fields, ["retired_at"] if system.get("retired_at") else [])
                return str(system["_id"])
            target = await (await self.target_repo()).get(target_id) or {}
            system = await repo.get_by_name(target_name)
            if system is not None:
                if isinstance(system.get("target_id"), str):
                    # The name is taken by a system that reports through another target.
                    log.info("inventory_system.name_linked_elsewhere", target_id=target_id, system_id=system["_id"])
                    return None
                await repo.update(str(system["_id"]), {"target_id": target_id}, ["retired_at"])
                await self._sync_target_classification(target_id, system, target, kind=kind, exposure=exposure)
                return str(system["_id"])
            kind = kind or target.get("kind")
            if not kind:
                return None
            system_id = str(uuid4())
            data = {"name": target_name, "kind": kind, "source": "sbom-import", "groups": [], "target_id": target_id}
            if exposure or target.get("exposure"):
                data["exposure"] = exposure or target.get("exposure")
            try:
                await repo.insert(system_id, data)
            except SystemNameTaken:
                return None
            return system_id
        except Exception:  # noqa: BLE001 - an import never fails over its system
            log.warning("inventory_system.link_import_failed", target_id=target_id, exc_info=True)
            return None

    async def _sync_target_classification(
        self,
        target_id: str,
        system: dict[str, Any],
        target: dict[str, Any],
        *,
        kind: str | None = None,
        exposure: str | None = None,
    ) -> None:
        """After linking: the import's values win, then the system's, then the target's; both get the result."""
        merged = {
            field: given or system.get(field) or target.get(field)
            for field, given in (("kind", kind), ("exposure", exposure))
        }
        merged = {k: v for k, v in merged.items() if v}
        if not merged:
            return
        await (await self.repo()).update(str(system["_id"]), merged)
        await (await self.target_repo()).update_classification(target_id, merged)

    async def apply_list(
        self,
        parsed: ParsedList,
        *,
        source: str,
        mode: str,
        dry_run: bool = False,
        force: bool = False,
    ) -> InventorySystemImportResponse:
        """Apply a server list: add and update its systems; in replace mode retire what it dropped.

        A list's fields win over what a system has (it is the record someone
        keeps); groups are set when the list names any. A system is retired only
        when the last list naming it drops it, so a system added by hand or by a
        push is never retired by a list it was never on. ``ListTooDestructive``
        guards replace mode against a broken export retiring most of a fleet.
        """
        repo = await self.repo()
        existing = {doc.get("name_key"): doc for doc in await repo.list_all()}
        listed_keys = {name_key(s.name) for s in parsed.systems}
        plan_create: list[tuple[str, dict[str, Any]]] = []
        plan_update: list[tuple[dict[str, Any], dict[str, Any], list[str]]] = []
        created, updated, restored, unchanged = [], [], [], 0
        for system in parsed.systems:
            doc = existing.get(name_key(system.name))
            if doc is None:
                data = {"name": system.name, "groups": system.groups, "source": "list",
                        "list_sources": [source], **system.fields}
                plan_create.append((str(uuid4()), data))
                created.append(system.name)
                continue
            set_fields: dict[str, Any] = {k: v for k, v in system.fields.items() if doc.get(k) != v}
            if system.groups and [g.casefold() for g in system.groups] != [g.casefold() for g in doc.get("groups") or []]:
                set_fields["groups"] = system.groups
            sources = list(doc.get("list_sources") or [])
            if source not in sources:
                set_fields["list_sources"] = [*sources, source]
            unset = ["retired_at"] if doc.get("retired_at") else []
            if unset:
                restored.append(doc["name"])
            if set_fields or unset:
                plan_update.append((doc, set_fields, unset))
                if set_fields.keys() - {"list_sources"}:
                    updated.append(doc["name"])
                elif not unset:
                    unchanged += 1
            else:
                unchanged += 1

        plan_retire: list[tuple[dict[str, Any], list[str]]] = []
        if mode == "replace":
            named_before = [doc for doc in existing.values() if source in (doc.get("list_sources") or [])]
            for doc in named_before:
                if doc.get("name_key") in listed_keys:
                    continue
                remaining = [s for s in doc.get("list_sources") or [] if s != source]
                plan_retire.append((doc, remaining))
            retiring = [doc for doc, remaining in plan_retire if not remaining and not doc.get("retired_at")]
            if not force and named_before and len(retiring) * 2 > len(named_before):
                raise ListTooDestructive(len(retiring), len(named_before))
        retired = [doc["name"] for doc, remaining in plan_retire if not remaining and not doc.get("retired_at")]

        if not dry_run:
            now = datetime.now(tz=UTC)
            for system_id, data in plan_create:
                try:
                    await repo.insert(system_id, data)
                except SystemNameTaken:  # created meanwhile (a push); the next sync updates it
                    created.remove(data["name"])
            for doc, set_fields, unset in plan_update:
                await repo.update(str(doc["_id"]), set_fields, unset)
                if isinstance(doc.get("target_id"), str) and {"kind", "exposure"} & set_fields.keys():
                    await (await self.target_repo()).update_classification(
                        doc["target_id"], {k: set_fields[k] for k in ("kind", "exposure") if k in set_fields},
                    )
            for doc, remaining in plan_retire:
                fields: dict[str, Any] = {"list_sources": remaining}
                if not remaining and not doc.get("retired_at"):
                    fields["retired_at"] = now
                await repo.update(str(doc["_id"]), fields)
            if plan_create:
                # A list naming a host that already pushed: link it now, not on its next push.
                for system_id, data in plan_create:
                    await self._link_existing_target(system_id, data["name"])

        cap = 200
        return InventorySystemImportResponse(
            format=parsed.format, source=source, mode=mode, dry_run=dry_run, listed=len(parsed.systems),
            created=created[:cap], updated=updated[:cap], retired=retired[:cap], restored=restored[:cap],
            created_count=len(created), updated_count=len(updated), unchanged_count=unchanged,
            retired_count=len(retired), restored_count=len(restored),
            skipped=parsed.skipped[:cap],
        )

    async def mirror_target_classification(self, target_id: str, fields: dict[str, str | None]) -> None:
        """Kind / exposure set on the target page reach the target's system too. Never raises."""
        try:
            repo = await self.repo()
            system = await repo.get_by_target(target_id)
            if system is None:
                return
            fields = {k: v for k, v in fields.items() if k in ("kind", "exposure")}
            await repo.update(
                str(system["_id"]),
                {k: v for k, v in fields.items() if v is not None},
                [k for k, v in fields.items() if v is None],
            )
        except Exception:  # noqa: BLE001
            log.warning("inventory_system.mirror_failed", target_id=target_id, exc_info=True)

    async def target_deleted(self, target_id: str) -> None:
        try:
            await (await self.repo()).unlink_target(target_id)
        except Exception:  # noqa: BLE001
            log.warning("inventory_system.unlink_failed", target_id=target_id, exc_info=True)

    async def backfill_from_targets(self) -> int:
        """Once per start: SBOM-import targets that say what they are become systems. Idempotent."""
        created = 0
        try:
            targets = await self.target_repo()
            linked = set(await (await self.repo()).linked_target_ids())
            cursor = targets.collection.find(
                {"type": "sbom-import", "kind": {"$type": "string"}}, projection={"name": 1, "kind": 1, "exposure": 1},
            )
            async for doc in cursor:
                target_id = str(doc["_id"])
                if target_id in linked:
                    continue
                if await self.link_import(target_id, doc.get("name") or target_id, doc.get("kind"), doc.get("exposure")):
                    created += 1
        except Exception:  # noqa: BLE001
            log.warning("inventory_system.backfill_failed", exc_info=True)
        if created:
            log.info("inventory_system.backfilled", systems=created)
        return created


_service: InventorySystemService | None = None


def get_inventory_system_service() -> InventorySystemService:
    global _service
    if _service is None:
        _service = InventorySystemService()
    return _service
