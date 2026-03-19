from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4
from zoneinfo import ZoneInfo

import httpx
import structlog

from app.core.config import settings
from app.db.mongo import get_database
from app.repositories.notification_rule_repository import NotificationRuleRepository
from app.schemas.notification import (
    NotificationRuleCreate,
    NotificationRuleResponse,
    NotificationTemplateCreate,
    NotificationTemplateResponse,
)

log = structlog.get_logger()


class NotificationService:
    """Sends notifications via an Apprise API service (caronc/apprise).

    Channels (Apprise URLs) are stored in MongoDB for reliability.
    Each notification request passes the matching URLs to Apprise's
    stateless ``POST /notify/`` endpoint.

    All public send methods are fire-and-forget safe — they log errors but
    never raise, so callers (ingestion jobs, scans, etc.) are never disrupted.
    """

    def __init__(self) -> None:
        self._base_url = settings.notifications_apprise_url.rstrip("/")
        self._tags = settings.notifications_apprise_tags
        self._timeout = settings.notifications_apprise_timeout

    @property
    def enabled(self) -> bool:
        return settings.notifications_enabled

    def _format_now(self) -> str:
        """Return the current timestamp formatted in the configured timezone."""
        import os
        tz = ZoneInfo(os.environ.get("TZ", "UTC"))
        return datetime.now(tz=tz).strftime("%Y-%m-%d %H:%M:%S %Z")

    # ------------------------------------------------------------------
    # Low-level send
    # ------------------------------------------------------------------

    async def send(
        self,
        title: str,
        body: str,
        *,
        notify_type: str = "info",
        tag: str | None = None,
    ) -> bool:
        """Send a notification via the stateless Apprise API.

        Loads matching channels from MongoDB, includes their URLs in the
        request, and sends via ``POST /notify/``.
        """
        if not self.enabled:
            return False

        tag_value = tag or self._tags or "all"

        # Resolve URLs from our stored channels
        urls = await self._resolve_urls(tag_value)
        if not urls:
            log.warning("notification.no_matching_channels", tag=tag_value, title=title)
            return False

        payload: dict[str, Any] = {
            "urls": urls,
            "title": title,
            "body": body,
            "type": notify_type,
        }

        url = f"{self._base_url}/notify/"
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.post(url, json=payload)
                if response.status_code < 300:
                    log.info("notification.sent", title=title, tag=tag_value)
                    return True
                # 424 = partial delivery (some targets succeeded, some failed)
                if response.status_code == 424:
                    log.warning(
                        "notification.partial_delivery",
                        status=response.status_code,
                        detail=response.text[:200],
                        title=title,
                    )
                    return True
                log.warning(
                    "notification.send_failed",
                    status=response.status_code,
                    detail=response.text[:200],
                    title=title,
                )
                return False
        except Exception as exc:
            log.warning("notification.send_error", error=str(exc), title=title)
            return False

    async def _resolve_urls(self, tag: str) -> list[str]:
        """Return Apprise URLs from MongoDB channels matching *tag*.

        - ``"all"`` matches every channel.
        - Otherwise, channels tagged ``"all"`` or with a matching tag are included.
        """
        channels = await self.list_channels()
        urls: list[str] = []
        for ch in channels:
            ch_tag = ch.get("tag") or "all"
            if tag == "all" or ch_tag == "all" or ch_tag == tag:
                urls.append(str(ch["url"]))
        return urls

    async def health(self) -> dict[str, object]:
        """Check whether the Apprise API is reachable."""
        if not self.enabled:
            return {"enabled": False, "reachable": False}

        url = f"{self._base_url}/status"
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.get(url)
                reachable = response.status_code < 400
        except Exception:
            reachable = False

        return {"enabled": True, "reachable": reachable}

    async def send_test(self, *, tag: str | None = None) -> bool:
        """Send a test notification."""
        return await self.send(
            title="Hecate \u2014 Test Notification",
            body=f"This is a test notification from Hecate.\nTimestamp: {self._format_now()}",
            notify_type="info",
            tag=tag,
        )

    # ------------------------------------------------------------------
    # Channel management (MongoDB-backed)
    # ------------------------------------------------------------------

    async def _get_channels_collection(self):
        db = await get_database()
        return db[settings.mongo_notification_channels_collection]

    async def list_channels(self) -> list[dict[str, Any]]:
        collection = await self._get_channels_collection()
        cursor = collection.find({}).sort("created_at", 1)
        docs: list[dict[str, Any]] = []
        async for doc in cursor:
            docs.append(doc)
        return docs

    async def add_channel(self, url: str, tag: str | None = None) -> dict[str, Any]:
        collection = await self._get_channels_collection()
        now = datetime.now(tz=UTC)
        doc = {
            "_id": str(uuid4()),
            "url": url,
            "tag": tag or "all",
            "created_at": now,
        }
        await collection.insert_one(doc)
        return doc

    async def remove_channel(self, channel_id: str) -> bool:
        collection = await self._get_channels_collection()
        result = await collection.delete_one({"_id": channel_id})
        return result.deleted_count > 0

    # ------------------------------------------------------------------
    # Rule CRUD
    # ------------------------------------------------------------------

    async def list_rules(self) -> list[NotificationRuleResponse]:
        repo = await NotificationRuleRepository.create()
        docs = await repo.list_all()
        return [self._map_rule(d) for d in docs]

    async def get_rule(self, rule_id: str) -> NotificationRuleResponse | None:
        repo = await NotificationRuleRepository.create()
        doc = await repo.get(rule_id)
        if doc is None:
            return None
        return self._map_rule(doc)

    async def create_rule(self, payload: NotificationRuleCreate) -> NotificationRuleResponse:
        repo = await NotificationRuleRepository.create()
        rule_id = str(uuid4())
        data = {
            "name": payload.name,
            "enabled": payload.enabled,
            "rule_type": payload.rule_type,
            "apprise_tag": payload.apprise_tag,
            "event_types": payload.event_types,
            "saved_search_id": payload.saved_search_id,
            "vendor_slug": payload.vendor_slug,
            "product_slug": payload.product_slug,
            "dql_query": payload.dql_query,
            "last_evaluated_at": None,
            "last_triggered_at": None,
        }
        doc = await repo.insert(rule_id, data)
        return self._map_rule(doc)

    async def update_rule(self, rule_id: str, payload: NotificationRuleCreate) -> NotificationRuleResponse | None:
        repo = await NotificationRuleRepository.create()
        existing = await repo.get(rule_id)
        if existing is None:
            return None
        updates = {
            "name": payload.name,
            "enabled": payload.enabled,
            "rule_type": payload.rule_type,
            "apprise_tag": payload.apprise_tag,
            "event_types": payload.event_types,
            "saved_search_id": payload.saved_search_id,
            "vendor_slug": payload.vendor_slug,
            "product_slug": payload.product_slug,
            "dql_query": payload.dql_query,
        }
        await repo.update(rule_id, updates)
        doc = await repo.get(rule_id)
        return self._map_rule(doc) if doc else None

    async def delete_rule(self, rule_id: str) -> bool:
        repo = await NotificationRuleRepository.create()
        return await repo.delete(rule_id)

    # ------------------------------------------------------------------
    # Event-based notification (checks event rules for routing)
    # ------------------------------------------------------------------

    async def notify_event(
        self,
        event_type: str,
        title: str,
        body: str,
        *,
        notify_type: str = "info",
    ) -> None:
        """Send notification for a system event, routing via matching event rules.

        If no event rules exist, falls back to the global default tag.
        """
        if not self.enabled:
            return

        repo = await NotificationRuleRepository.create()
        rules = await repo.list_enabled_by_type("event")

        matching = [r for r in rules if event_type in r.get("event_types", [])]

        if matching:
            for rule in matching:
                tag = rule.get("apprise_tag", self._tags)
                await self.send(title, body, notify_type=notify_type, tag=tag)
                await repo.update(str(rule["_id"]), {"last_triggered_at": datetime.now(tz=UTC)})
        else:
            # No event rules configured — send to all channels
            await self.send(title, body, notify_type=notify_type)

    async def notify_scan_completed(
        self,
        *,
        scan_id: str,
        target: str,
        status: str,
        findings_count: int,
        duration_seconds: float,
    ) -> None:
        icon = "\u2705" if status == "completed" else "\u274c"
        event_type = "scan_completed" if status == "completed" else "scan_failed"
        notify_type = "success" if status == "completed" else "failure"
        variables = {
            "icon": icon,
            "target": target,
            "status": status,
            "findings": str(findings_count),
            "duration": f"{duration_seconds:.1f}",
            "scan_id": scan_id,
        }
        default_title = f"{icon} Hecate \u2014 SCA Scan {status.title()}"
        default_body = f"Target: {target}\nStatus: {status}\nFindings: {findings_count}\nDuration: {duration_seconds:.1f}s\nScan ID: {scan_id}"
        title, body = await self._apply_template(event_type, None, variables, default_title, default_body)
        await self.notify_event(event_type, title, body, notify_type=notify_type)

    async def notify_sync_failed(self, *, job_name: str, error: str) -> None:
        now_str = self._format_now()
        variables = {
            "job_name": job_name,
            "error": error[:500],
            "time": now_str,
        }
        default_title = f"\u274c Hecate \u2014 Sync Failed: {job_name}"
        default_body = f"Job: {job_name}\nError: {error[:500]}\nTime: {now_str}"
        title, body = await self._apply_template("sync_failed", None, variables, default_title, default_body)
        await self.notify_event("sync_failed", title, body, notify_type="failure")

    async def notify_new_vulnerabilities_event(self, *, source: str, inserted: int) -> None:
        if inserted <= 0:
            return
        now_str = self._format_now()
        variables = {
            "icon": "\U0001f195",
            "source": source,
            "count": str(inserted),
            "noun": "Vulnerability" if inserted == 1 else "Vulnerabilities",
            "time": now_str,
        }
        default_title = f"\U0001f195 Hecate \u2014 {inserted} New {variables['noun']}"
        default_body = f"Source: {source}\nNew entries: {inserted}\nTime: {now_str}"
        title, body = await self._apply_template("new_vulnerabilities", None, variables, default_title, default_body)
        await self.notify_event("new_vulnerabilities", title, body, notify_type="info")

    # ------------------------------------------------------------------
    # Watch-rule evaluation (saved_search, vendor, product, dql)
    # ------------------------------------------------------------------

    async def evaluate_watch_rules(self) -> None:
        """Evaluate all enabled watch rules and send notifications for matches.

        Called after ingestion pipelines insert new vulnerabilities.
        """
        if not self.enabled:
            return

        repo = await NotificationRuleRepository.create()
        rules = await repo.list_enabled()
        watch_rules = [
            r for r in rules if r.get("rule_type") in ("saved_search", "vendor", "product", "dql")
        ]

        if not watch_rules:
            return

        # Import here to avoid circular imports
        from app.services.vulnerability_service import VulnerabilityService

        vuln_service = VulnerabilityService()

        for rule in watch_rules:
            try:
                await self._evaluate_single_watch_rule(rule, vuln_service, repo)
            except Exception as exc:
                log.warning(
                    "notification.rule_evaluation_failed",
                    rule_id=str(rule["_id"]),
                    rule_name=rule.get("name"),
                    error=str(exc),
                )

    async def _evaluate_single_watch_rule(
        self,
        rule: dict[str, Any],
        vuln_service: Any,
        repo: NotificationRuleRepository,
    ) -> None:
        from app.schemas.vulnerability import VulnerabilityQuery

        rule_type = rule.get("rule_type")
        rule_id = str(rule["_id"])
        rule_name = rule.get("name", "Unnamed Rule")
        tag = rule.get("apprise_tag", self._tags)

        last_checked = rule.get("last_evaluated_at")
        now = datetime.now(tz=UTC)

        # Build time filter for "only new since last check"
        time_dql = ""
        if last_checked:
            iso = last_checked.strftime("%Y-%m-%dT%H:%M:%SZ")
            time_dql = f'ingested_at:>="{iso}"'

        query: VulnerabilityQuery | None = None

        if rule_type == "vendor":
            vendor_slug = rule.get("vendor_slug")
            if not vendor_slug:
                return
            query = VulnerabilityQuery(
                search_term=None,
                dql_query=time_dql or None,
                vendor_slugs=[vendor_slug],
                limit=10,
            )

        elif rule_type == "product":
            product_slug = rule.get("product_slug")
            if not product_slug:
                return
            query = VulnerabilityQuery(
                search_term=None,
                dql_query=time_dql or None,
                product_slugs=[product_slug],
                limit=10,
            )

        elif rule_type == "dql":
            dql = rule.get("dql_query")
            if not dql:
                return
            combined_dql = f"({dql}) AND {time_dql}" if time_dql else dql
            query = VulnerabilityQuery(
                search_term=None,
                dql_query=combined_dql,
                limit=10,
            )

        elif rule_type == "saved_search":
            query = await self._build_saved_search_query(rule, time_dql)

        if query is None:
            await repo.update(rule_id, {"last_evaluated_at": now})
            return

        results = await vuln_service.search(query)
        await repo.update(rule_id, {"last_evaluated_at": now})

        if results:
            count = len(results)
            now_str = self._format_now()

            # Collect aggregate vendor/product/version info
            all_vendors: set[str] = set()
            all_products: set[str] = set()
            all_versions: set[str] = set()
            vuln_details: list[dict[str, str]] = []
            for r in results:
                all_vendors.update(r.vendors)
                all_products.update(r.products)
                all_versions.update(r.product_versions)
                vuln_details.append({
                    "id": r.vuln_id,
                    "severity": r.severity or "N/A",
                    "cvss": str(r.cvss_score) if r.cvss_score is not None else "N/A",
                    "cwes": ", ".join(r.cwes) if r.cwes else "N/A",
                    "summary": (r.summary[:200] + "…") if len(r.summary) > 200 else r.summary,
                    "title": (r.title[:120] + "…") if len(r.title) > 120 else r.title,
                    "vendors": ", ".join(r.vendors) if r.vendors else "N/A",
                    "products": ", ".join(r.products) if r.products else "N/A",
                    "versions": ", ".join(r.product_versions[:5]) if r.product_versions else "N/A",
                    "exploited": "Yes" if r.exploited else "No",
                    "source": r.source or "N/A",
                    "published": r.published.strftime("%Y-%m-%d") if r.published else "N/A",
                })

            vuln_ids_str = ", ".join(r.vuln_id for r in results[:10])
            variables = {
                "icon": "\U0001f6a8",
                "rule_name": rule_name,
                "count": str(count),
                "noun": "Vulnerability" if count == 1 else "Vulnerabilities",
                "vulnerabilities_list": vuln_ids_str,
                "vendors": ", ".join(sorted(all_vendors)[:10]) if all_vendors else "N/A",
                "products": ", ".join(sorted(all_products)[:10]) if all_products else "N/A",
                "versions": ", ".join(sorted(all_versions)[:10]) if all_versions else "N/A",
                "time": now_str,
                "vulnerabilities": vuln_details,
            }
            default_title = f"\U0001f6a8 Hecate \u2014 {count} New {variables['noun']}: {rule_name}"
            default_body_lines = [
                f"Rule: {rule_name}",
                f"Matches: {count}",
                f"Vulnerabilities: {vuln_ids_str}",
                f"Time: {now_str}",
            ]
            default_body = "\n".join(default_body_lines)
            title, body = await self._apply_template("watch_rule_match", tag, variables, default_title, default_body)
            await self.send(
                title=title,
                body=body,
                notify_type="warning",
                tag=tag,
            )
            await repo.update(rule_id, {"last_triggered_at": now})

    async def _build_saved_search_query(
        self,
        rule: dict[str, Any],
        time_dql: str,
    ) -> Any | None:
        """Build a VulnerabilityQuery from a saved search reference."""
        from urllib.parse import parse_qsl

        from app.repositories.saved_search_repository import SavedSearchRepository
        from app.schemas.vulnerability import VulnerabilityQuery

        search_id = rule.get("saved_search_id")
        if not search_id:
            return None

        search_repo = await SavedSearchRepository.create()
        saved = await search_repo.get(search_id)
        if saved is None:
            return None

        # Check if saved search has a DQL query
        dql = saved.get("dqlQuery")
        if dql:
            combined = f"({dql}) AND {time_dql}" if time_dql else dql
            return VulnerabilityQuery(search_term=None, dql_query=combined, limit=10)

        # Parse queryParams (URL query string fragment)
        raw_params = saved.get("queryParams", "")
        params = dict(parse_qsl(raw_params))

        # Check if this is a DQL-mode search
        if params.get("mode") == "dql" and params.get("search"):
            dql = params["search"]
            combined = f"({dql}) AND {time_dql}" if time_dql else dql
            return VulnerabilityQuery(search_term=None, dql_query=combined, limit=10)

        # Build from standard params
        def _split(key: str) -> list[str]:
            val = params.get(key, "")
            return [v for v in val.split(",") if v.strip()] if val else []

        search_term = params.get("search") or None
        combined_dql = time_dql or None

        # If there's a search term and a time filter, use DQL to combine
        if search_term and time_dql:
            combined_dql = f'({search_term}) AND {time_dql}'
            search_term = None

        return VulnerabilityQuery(
            search_term=search_term,
            dql_query=combined_dql,
            vendor_slugs=_split("vendorSlugs"),
            product_slugs=_split("productSlugs"),
            severity=_split("severity"),
            exploited_only=params.get("exploitedOnly") == "true",
            limit=10,
        )

    # ------------------------------------------------------------------
    # Message Template CRUD
    # ------------------------------------------------------------------

    async def _get_templates_collection(self):
        db = await get_database()
        return db[settings.mongo_notification_templates_collection]

    async def list_templates(self) -> list[NotificationTemplateResponse]:
        collection = await self._get_templates_collection()
        cursor = collection.find({}).sort("event_key", 1)
        docs: list[dict[str, Any]] = []
        async for doc in cursor:
            docs.append(doc)
        return [self._map_template(d) for d in docs]

    async def get_template(self, template_id: str) -> NotificationTemplateResponse | None:
        collection = await self._get_templates_collection()
        doc = await collection.find_one({"_id": template_id})
        if doc is None:
            return None
        return self._map_template(doc)

    async def create_template(self, payload: NotificationTemplateCreate) -> NotificationTemplateResponse:
        collection = await self._get_templates_collection()
        now = datetime.now(tz=UTC)
        template_id = str(uuid4())
        doc = {
            "_id": template_id,
            "event_key": payload.event_key,
            "tag": payload.tag,
            "title_template": payload.title_template,
            "body_template": payload.body_template,
            "created_at": now,
            "updated_at": now,
        }
        await collection.insert_one(doc)
        return self._map_template(doc)

    async def update_template(
        self, template_id: str, payload: NotificationTemplateCreate
    ) -> NotificationTemplateResponse | None:
        collection = await self._get_templates_collection()
        existing = await collection.find_one({"_id": template_id})
        if existing is None:
            return None
        now = datetime.now(tz=UTC)
        updates = {
            "event_key": payload.event_key,
            "tag": payload.tag,
            "title_template": payload.title_template,
            "body_template": payload.body_template,
            "updated_at": now,
        }
        await collection.update_one({"_id": template_id}, {"$set": updates})
        doc = await collection.find_one({"_id": template_id})
        return self._map_template(doc) if doc else None

    async def delete_template(self, template_id: str) -> bool:
        collection = await self._get_templates_collection()
        result = await collection.delete_one({"_id": template_id})
        return result.deleted_count > 0

    async def _apply_template(
        self,
        event_key: str,
        tag: str | None,
        variables: dict[str, Any],
        default_title: str,
        default_body: str,
    ) -> tuple[str, str]:
        """Apply a message template if one exists, otherwise return defaults."""
        tpl = await self._resolve_template(event_key, tag)
        if tpl is None:
            return default_title, default_body
        title_tpl, body_tpl = tpl
        return self._render_template(title_tpl, variables), self._render_template(body_tpl, variables)

    async def _resolve_template(
        self, event_key: str, tag: str | None
    ) -> tuple[str, str] | None:
        """Find the best matching template for an event + tag combo.

        Priority: exact tag match -> "all" fallback -> None (use hardcoded default).
        """
        collection = await self._get_templates_collection()
        # Try exact tag match first
        if tag and tag != "all":
            doc = await collection.find_one({"event_key": event_key, "tag": tag})
            if doc:
                return doc["title_template"], doc["body_template"]
        # Fallback to global "all" template
        doc = await collection.find_one({"event_key": event_key, "tag": "all"})
        if doc:
            return doc["title_template"], doc["body_template"]
        return None

    def _render_template(
        self, template: str, variables: dict[str, Any]
    ) -> str:
        """Render a template string with {placeholder} variables and {#each list}...{/each} loops.

        Loop syntax:
            {#each vulnerabilities}
            {id} — {severity} ({cvss}) — {summary}
            {/each}

        Inside a loop block, placeholders resolve against each item dict.
        Top-level placeholders are resolved outside loop blocks.
        Unknown placeholders are left as-is.
        """
        import re

        result = template

        # Process {#each <key>}...{/each} blocks
        each_pattern = re.compile(r"\{#each\s+(\w+)\}(.*?)\{/each\}", re.DOTALL)
        def _expand_each(match: re.Match[str]) -> str:
            list_key = match.group(1)
            block_tpl = match.group(2)
            # Strip one leading newline if present (so template formatting looks clean)
            if block_tpl.startswith("\n"):
                block_tpl = block_tpl[1:]
            if block_tpl.endswith("\n"):
                block_tpl = block_tpl[:-1]
            items = variables.get(list_key)
            if not isinstance(items, list) or not items:
                return ""
            rendered_items: list[str] = []
            for item in items:
                line = block_tpl
                if isinstance(item, dict):
                    for k, v in item.items():
                        line = line.replace(f"{{{k}}}", str(v))
                else:
                    line = line.replace("{item}", str(item))
                rendered_items.append(line)
            return "\n".join(rendered_items)

        result = each_pattern.sub(_expand_each, result)

        # Process top-level scalar placeholders
        for key, value in variables.items():
            if not isinstance(value, list):
                result = result.replace(f"{{{key}}}", str(value))
        return result

    def _map_template(self, doc: dict[str, Any]) -> NotificationTemplateResponse:
        return NotificationTemplateResponse(
            id=str(doc.get("_id", "")),
            event_key=doc.get("event_key", ""),
            tag=doc.get("tag", "all"),
            title_template=doc.get("title_template", ""),
            body_template=doc.get("body_template", ""),
            created_at=doc.get("created_at", datetime.now(tz=UTC)),
            updated_at=doc.get("updated_at", datetime.now(tz=UTC)),
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _map_rule(self, doc: dict[str, Any]) -> NotificationRuleResponse:
        return NotificationRuleResponse(
            id=str(doc.get("_id", "")),
            name=doc.get("name", ""),
            enabled=doc.get("enabled", True),
            rule_type=doc.get("rule_type", "event"),
            apprise_tag=doc.get("apprise_tag", "all"),
            event_types=doc.get("event_types", []),
            saved_search_id=doc.get("saved_search_id"),
            vendor_slug=doc.get("vendor_slug"),
            product_slug=doc.get("product_slug"),
            dql_query=doc.get("dql_query"),
            created_at=doc.get("created_at", datetime.now(tz=UTC)),
            updated_at=doc.get("updated_at", datetime.now(tz=UTC)),
            last_evaluated_at=doc.get("last_evaluated_at"),
            last_triggered_at=doc.get("last_triggered_at"),
        )


def get_notification_service() -> NotificationService:
    return NotificationService()
