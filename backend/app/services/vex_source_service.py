"""
VEX sources: VEX documents attached to a scan target and applied after every scan.

A vendor that publishes a VEX document for its image (Hecate does, in vex/) lets
the image's users skip triaging the same findings again. The target owner enters
the document's URL once; after each scan Hecate fetches it, reads CycloneDX VEX
or OpenVEX, and sets the status of the matching findings.

Two rules keep the vendor's word below the owner's own:
  - only findings without a VEX status, or with one from a VEX source
    (``vex_updated_by == "vex-source"``), are set; a hand-set or imported one stays;
  - a source status whose vulnerability no source mentions any more is removed,
    but only when every source could be read, so a failed fetch never wipes them.

The URL comes from a target owner, not only the admin, so the fetch is guarded:
https only, no credentials in the URL, public addresses only (the same check as
the advisory feeds, ``SCA_VEX_SOURCES_ALLOW_PRIVATE_HOSTS`` lifts it), no
redirects, a size cap, and errors reported as a short category only, since the
target and its status are public.
"""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import unquote, urlsplit

import httpx
import structlog

from app.core.config import settings
from app.repositories.scan_finding_repository import ScanFindingRepository
from app.repositories.scan_target_repository import ScanTargetRepository
from app.services.http.public_host import is_public_url
from app.services.http.ssl import get_http_verify
from app.services.vex_service import CYCLONEDX_STATE_TO_VEX, _vex_text

log = structlog.get_logger()

MAX_VEX_SOURCES = 5
MAX_URL_LENGTH = 2048
_OPENVEX_STATUSES = {"not_affected", "affected", "fixed", "under_investigation"}


class VexSourceError(Exception):
    """A source that could not be used. ``kind`` is what the UI shows."""

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind
        self.message = message


@dataclass
class VexStatement:
    ids: list[str]
    status: str
    justification: str | None = None
    detail: str | None = None
    packages: list[str] = field(default_factory=list)


# ---------------------------------------------------------------- URLs


def _github_raw(url: str) -> str:
    """github.com/<owner>/<repo>/blob/<ref>/<path> serves HTML; its raw file is meant."""
    parts = urlsplit(url)
    if parts.hostname not in ("github.com", "www.github.com"):
        return url
    segments = parts.path.strip("/").split("/")
    if len(segments) >= 5 and segments[2] == "blob":
        owner, repo, _, *rest = segments
        return f"https://raw.githubusercontent.com/{owner}/{repo}/{'/'.join(rest)}"
    return url


def normalize_vex_source_urls(urls: Any) -> list[str]:
    """Validated, de-duplicated source URLs. Raises ``ValueError`` with the reason."""
    if not isinstance(urls, list):
        raise ValueError("vexSources must be a list of URLs")
    result: list[str] = []
    for raw in urls:
        if not isinstance(raw, str):
            raise ValueError("vexSources must be a list of URLs")
        url = raw.strip()
        if not url:
            continue
        if len(url) > MAX_URL_LENGTH:
            raise ValueError("A VEX source URL is too long")
        parts = urlsplit(url)
        if parts.scheme != "https" or not parts.hostname:
            raise ValueError(f"Not an https URL: {url[:200]}")
        # Targets are public, and so are their VEX sources.
        if parts.username or parts.password:
            raise ValueError("A VEX source URL must not contain credentials")
        url = _github_raw(url)
        if url not in result:
            result.append(url)
    if len(result) > MAX_VEX_SOURCES:
        raise ValueError(f"At most {MAX_VEX_SOURCES} VEX sources per target")
    return result


# ---------------------------------------------------------------- fetching


async def fetch_vex_document(url: str) -> dict[str, Any]:
    if not settings.sca_vex_sources_allow_private_hosts and not await is_public_url(url):
        raise VexSourceError("not_public", "The host does not resolve to a public address.")
    limit = settings.sca_vex_source_max_bytes
    try:
        async with httpx.AsyncClient(
            verify=get_http_verify(),
            timeout=httpx.Timeout(settings.sca_vex_source_timeout_seconds, connect=10.0),
            follow_redirects=False,
            headers={"User-Agent": settings.ingestion_user_agent, "Accept": "application/json"},
        ) as client:
            async with client.stream("GET", url) as response:
                if response.status_code != 200:
                    raise VexSourceError("http_status", f"The server answered HTTP {response.status_code}.")
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > limit:
                        raise VexSourceError("too_large", f"The document is larger than {limit} bytes.")
    except httpx.HTTPError as exc:
        raise VexSourceError("network", f"The request failed ({type(exc).__name__}).") from exc
    try:
        document = json.loads(bytes(body))
    except ValueError as exc:
        raise VexSourceError("invalid_json", "The document is not JSON.") from exc
    if not isinstance(document, dict):
        raise VexSourceError("unknown_format", "The document is neither CycloneDX VEX nor OpenVEX.")
    return document


# ---------------------------------------------------------------- parsing


def _ids(primary: Any, aliases: Any) -> list[str]:
    values = [primary] + (aliases if isinstance(aliases, list) else [])
    out: list[str] = []
    for value in values:
        if isinstance(value, str) and value.strip() and len(value) <= 128:
            for variant in (value.strip(), value.strip().upper()):
                if variant not in out:
                    out.append(variant)
    return out


def package_names_from_purl(purl: str) -> list[str]:
    """The spellings a finding's ``package_name`` may use for a purl."""
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        return []
    path = purl[4:].split("#", 1)[0].split("?", 1)[0].split("@", 1)[0]
    segments = [unquote(s) for s in path.split("/")[1:] if s]
    if not segments:
        return []
    name = segments[-1]
    namespace = "/".join(segments[:-1])
    names = [name]
    if namespace:
        names += [f"{namespace}/{name}", f"{namespace}:{name}"]
    return names


def _parse_cyclonedx(document: dict[str, Any]) -> list[VexStatement]:
    by_ref: dict[str, list[str]] = {}
    for component in document.get("components") or []:
        if not isinstance(component, dict):
            continue
        names = package_names_from_purl(component.get("purl", ""))
        if isinstance(component.get("name"), str):
            names.append(component["name"])
        if isinstance(component.get("bom-ref"), str):
            by_ref[component["bom-ref"]] = names
    statements = []
    for vuln in document.get("vulnerabilities") or []:
        if not isinstance(vuln, dict):
            continue
        analysis = vuln.get("analysis")
        state = analysis.get("state") if isinstance(analysis, dict) else None
        status = CYCLONEDX_STATE_TO_VEX.get(state) if isinstance(state, str) else None
        aliases = [r.get("id") for r in vuln.get("references") or [] if isinstance(r, dict)]
        ids = _ids(vuln.get("id"), aliases)
        if not status or not ids:
            continue
        packages: list[str] = []
        for affect in vuln.get("affects") or []:
            ref = affect.get("ref") if isinstance(affect, dict) else None
            if isinstance(ref, str):
                packages += by_ref.get(ref) or package_names_from_purl(ref) or [ref]
        statements.append(VexStatement(
            ids=ids,
            status=status,
            justification=_vex_text(analysis.get("justification")),
            detail=_vex_text(analysis.get("detail")),
            packages=sorted(set(packages)),
        ))
    return statements


def _parse_openvex(document: dict[str, Any]) -> list[VexStatement]:
    statements = []
    for st in document.get("statements") or []:
        if not isinstance(st, dict):
            continue
        status = st.get("status")
        vuln = st.get("vulnerability")
        if isinstance(vuln, dict):
            ids = _ids(vuln.get("name") or vuln.get("@id"), vuln.get("aliases"))
        else:  # OpenVEX 0.0.x: the vulnerability is a plain string
            ids = _ids(vuln, None)
        if status not in _OPENVEX_STATUSES or not ids:
            continue
        packages: list[str] = []
        for product in st.get("products") or []:
            if not isinstance(product, dict):
                continue
            subs = [s.get("@id") for s in product.get("subcomponents") or [] if isinstance(s, dict)]
            # The image itself (pkg:oci/...) names no package; its subcomponents do.
            for purl in subs or ([product.get("@id")] if not str(product.get("@id", "")).startswith("pkg:oci/") else []):
                packages += package_names_from_purl(purl or "")
        detail = st.get("impact_statement") or st.get("action_statement") or st.get("status_notes")
        statements.append(VexStatement(
            ids=ids,
            status=status,
            justification=_vex_text(st.get("justification")),
            detail=_vex_text(detail),
            packages=sorted(set(packages)),
        ))
    return statements


def parse_vex_document(document: dict[str, Any]) -> tuple[str, list[VexStatement]]:
    if document.get("bomFormat") == "CycloneDX" and isinstance(document.get("vulnerabilities"), list):
        return "cyclonedx", _parse_cyclonedx(document)
    context = document.get("@context")
    if isinstance(document.get("statements"), list) and isinstance(context, str) and "openvex" in context:
        return "openvex", _parse_openvex(document)
    raise VexSourceError("unknown_format", "The document is neither CycloneDX VEX nor OpenVEX.")


# ---------------------------------------------------------------- applying


class VexSourceService:
    def __init__(self, target_repo: ScanTargetRepository, finding_repo: ScanFindingRepository) -> None:
        self.target_repo = target_repo
        self.finding_repo = finding_repo

    async def apply_statements(self, target_id: str, statements: list[VexStatement]) -> tuple[int, int]:
        """Apply statements to the target's findings. Returns (findings set, statements skipped).

        When the documents give one vulnerability different statuses for
        different packages, a statement only reaches the packages it names;
        otherwise it covers every finding of that vulnerability, so a package
        spelled differently by the scanner still gets it.
        """
        statuses: dict[str, set[str]] = defaultdict(set)
        for st in statements:
            for vid in st.ids:
                statuses[vid].add(st.status)
        applied = skipped = 0
        for st in statements:
            ambiguous = any(len(statuses[vid]) > 1 for vid in st.ids)
            if ambiguous and not st.packages:
                skipped += 1
                continue
            applied += await self.finding_repo.apply_vex_from_source(
                target_id,
                st.ids,
                st.status,
                package_names=st.packages if ambiguous else None,
                vex_justification=st.justification or st.detail,
                vex_detail=st.detail,
            )
        return applied, skipped

    async def apply_target_sources(self, target_id: str) -> dict[str, Any] | None:
        """Fetch and apply the target's VEX sources. ``None`` when it has none.

        The outcome is stored on the target as ``vex_source_status``:
        ``{checked_at, applied, skipped, cleared, sources: [{url, ok, format,
        statements} | {url, ok: false, error_kind, error}]}``.
        """
        target = await self.target_repo.get(target_id)
        urls = (target or {}).get("vex_sources") or []
        if not urls:
            return None
        sources: list[dict[str, Any]] = []
        statements: list[VexStatement] = []
        for url in urls:
            try:
                fmt, found = parse_vex_document(await fetch_vex_document(url))
                sources.append({"url": url, "ok": True, "format": fmt, "statements": len(found)})
                statements += found
            except VexSourceError as exc:
                sources.append({"url": url, "ok": False, "error_kind": exc.kind, "error": exc.message})
                log.info("vex_source.unusable", target_id=target_id, url=url, kind=exc.kind)

        # Ambiguity is judged across all sources, so they are applied together.
        applied, skipped = await self.apply_statements(target_id, statements)
        cleared = 0
        if all(source["ok"] for source in sources):
            keep = sorted({vid for st in statements for vid in st.ids})
            cleared = await self.finding_repo.clear_vex_source_statuses(target_id, keep)
        status = {
            "checked_at": datetime.now(tz=UTC),
            "applied": applied,
            "skipped": skipped,
            "cleared": cleared,
            "sources": sources,
        }
        await self.target_repo.set_vex_source_status(target_id, status)
        log.info("vex_source.applied", target_id=target_id, sources=len(urls),
                 applied=applied, skipped=skipped, cleared=cleared)
        return status
