from __future__ import annotations

import asyncio
import re
import time
from datetime import UTC, datetime
from importlib import metadata as importlib_metadata
from pathlib import Path
from typing import Any

import httpx
import structlog
from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.core.config import settings
from app.schemas._utc import UtcDatetime
from app.services.http.retry import request_with_retry
from app.services.http.ssl import get_http_verify

router = APIRouter()
log = structlog.get_logger()

GITHUB_OWNER = "0x3e4"
GITHUB_REPO = "hecate"
REPO_URL = f"https://github.com/{GITHUB_OWNER}/{GITHUB_REPO}"
KOFI_URL = "https://ko-fi.com/0x3e4"

# Image names match the GitHub Actions build matrix (`hecate-${component}`).
COMPONENT_IMAGES: dict[str, str] = {
    "backend": "hecate-backend",
    "frontend": "hecate-frontend",
    "scanner": "hecate-scanner",
}

CACHE_TTL_SECONDS = 3600
SCANNER_PROBE_TIMEOUT = 3.0
_FALLBACK_VERSION = "1.0.0"
_SHORT_SHA_LEN = 7
_BUILD_SHA_FILE = Path("/app/.build_sha")
# Optional bind-mount targets the user can add to their docker-compose.yml so
# the backend can self-detect its SHA when building locally (no CI build-arg
# available). Read-only, parsed without needing a git binary.
_GIT_FALLBACK_PATHS = (Path("/host/.git"), Path("/repo/.git"))

# Match semver-ish git tags: optional `v` prefix, 2 or 3 numeric segments,
# optional pre-release suffix (`-rc.1`, `-beta`, …).
_SEMVER_TAG_RE = re.compile(r"^v?(\d+)\.(\d+)(?:\.(\d+))?(?:[-+].+)?$")
# Match docker/metadata-action's `type=sha,prefix={{branch}}-` output, e.g.
# `main-f637374`. The hex part is whatever length GitHub's short-sha returns
# (7+ chars).
_BUILD_TAG_RE = re.compile(r"^main-([0-9a-f]{7,40})$", re.IGNORECASE)


def _read_current_version() -> str:
    try:
        return importlib_metadata.version("hecate-backend")
    except importlib_metadata.PackageNotFoundError:
        return _FALLBACK_VERSION


CURRENT_VERSION = _read_current_version()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class LatestBuild(BaseModel):
    tag: str
    short_sha: str = Field(alias="shortSha", serialization_alias="shortSha")
    published_at: UtcDatetime | None = Field(
        default=None, alias="publishedAt", serialization_alias="publishedAt"
    )
    package_url: str | None = Field(
        default=None, alias="packageUrl", serialization_alias="packageUrl"
    )
    model_config = {"populate_by_name": True}


class RunningComponent(BaseModel):
    """Self-reported identity of a running container.

    ``reachable`` is informational — for components the backend probes over
    the network (currently just the scanner). The backend itself is always
    reachable (this very endpoint is on it), and the frontend is queried by
    the React app from its own bundle, never by the backend.
    """
    running_sha: str | None = Field(
        default=None, alias="runningSha", serialization_alias="runningSha"
    )
    running_version: str | None = Field(
        default=None, alias="runningVersion", serialization_alias="runningVersion"
    )
    reachable: bool = True
    model_config = {"populate_by_name": True}


class GhcrLatest(BaseModel):
    backend: LatestBuild | None = None
    frontend: LatestBuild | None = None
    scanner: LatestBuild | None = None
    model_config = {"populate_by_name": True}


class SemverTag(BaseModel):
    tag: str
    release_url: str = Field(alias="releaseUrl", serialization_alias="releaseUrl")
    model_config = {"populate_by_name": True}


class VersionInfoResponse(BaseModel):
    backend: RunningComponent
    scanner: RunningComponent
    ghcr: GhcrLatest
    semver_tag: SemverTag | None = Field(
        default=None, alias="semverTag", serialization_alias="semverTag"
    )
    repo_url: str = Field(alias="repoUrl", serialization_alias="repoUrl")
    kofi_url: str = Field(alias="kofiUrl", serialization_alias="kofiUrl")
    checked_at: UtcDatetime = Field(alias="checkedAt", serialization_alias="checkedAt")
    model_config = {"populate_by_name": True}


# ---------------------------------------------------------------------------
# Build SHA resolution (backend's own identity)
# ---------------------------------------------------------------------------


def _short_sha(value: str) -> str:
    return value.strip().lower()[:_SHORT_SHA_LEN]


def _read_sha_from_git_dir(git_dir: Path) -> str | None:
    """Parse ``.git/HEAD`` without invoking the git binary.

    Handles the two common shapes:

    * Detached HEAD: ``HEAD`` contains a 40-char SHA directly.
    * Branch HEAD: ``HEAD`` contains ``ref: refs/heads/<branch>`` and the
      SHA lives in ``.git/refs/heads/<branch>``.

    Packed refs (``.git/packed-refs``) and worktree gitfiles (``.git`` is a
    file, not a dir) are not handled — uncommon in a docker-compose deploy
    folder, and the user can fall back to setting ``HECATE_BUILD_SHA`` as
    an env var if needed.
    """
    try:
        head = (git_dir / "HEAD").read_text().strip()
    except (FileNotFoundError, NotADirectoryError, PermissionError, OSError):
        return None
    if not head:
        return None
    if head.startswith("ref: "):
        ref_path = git_dir / head[len("ref: "):].strip()
        try:
            return ref_path.read_text().strip() or None
        except (FileNotFoundError, OSError):
            return None
    return head


def _read_build_sha() -> str | None:
    """Resolve the running backend's build SHA.

    Resolution order:
      1. ``/app/.build_sha`` — file baked at image build time by CI.
      2. ``/host/.git`` or ``/repo/.git`` — bind-mounted host git directory
         for users who run ``docker compose build`` locally.
      3. ``HECATE_BUILD_SHA`` env var — last resort for non-Docker dev runs.
    """
    try:
        raw = _BUILD_SHA_FILE.read_text().strip()
    except (FileNotFoundError, PermissionError, OSError):
        raw = ""
    if raw:
        return _short_sha(raw)
    for git_dir in _GIT_FALLBACK_PATHS:
        sha = _read_sha_from_git_dir(git_dir)
        if sha:
            return _short_sha(sha)
    raw = (settings.hecate_build_sha or "").strip()
    return _short_sha(raw) if raw else None


# ---------------------------------------------------------------------------
# Scanner sidecar probe
# ---------------------------------------------------------------------------


async def _probe_scanner() -> RunningComponent:
    """Hit the scanner sidecar's /version endpoint over the compose network.

    Fail-soft: a timeout or 5xx returns a placeholder marked
    ``reachable=False`` so the Support page can render "Scanner unreachable"
    without breaking the rest of the response.
    """
    base = (settings.sca_scanner_url or "").rstrip("/")
    if not base:
        return RunningComponent(reachable=False)
    url = f"{base}/version"
    try:
        async with httpx.AsyncClient(
            verify=get_http_verify(),
            timeout=httpx.Timeout(SCANNER_PROBE_TIMEOUT, connect=2.0),
        ) as client:
            resp = await client.get(url)
    except httpx.HTTPError as exc:
        log.info("version_check.scanner_unreachable", error=str(exc))
        return RunningComponent(reachable=False)
    if resp.status_code != 200:
        log.info("version_check.scanner_unreachable", status=resp.status_code)
        return RunningComponent(reachable=False)
    try:
        payload = resp.json()
    except ValueError:
        return RunningComponent(reachable=False)
    raw_sha = payload.get("buildSha") if isinstance(payload, dict) else None
    sha = _short_sha(raw_sha) if isinstance(raw_sha, str) and raw_sha else None
    version = payload.get("version") if isinstance(payload, dict) else None
    return RunningComponent(
        running_sha=sha,
        running_version=version if isinstance(version, str) else None,
        reachable=True,
    )


# ---------------------------------------------------------------------------
# Semver helpers
# ---------------------------------------------------------------------------


def _parse_semver(tag: str) -> tuple[int, int, int] | None:
    match = _SEMVER_TAG_RE.match(tag.strip())
    if not match:
        return None
    return (int(match.group(1)), int(match.group(2)), int(match.group(3) or "0"))


# ---------------------------------------------------------------------------
# GitHub API calls
# ---------------------------------------------------------------------------


def _github_headers() -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": settings.ingestion_user_agent or "hecate-version-check",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if settings.ghsa_token:
        headers["Authorization"] = f"Bearer {settings.ghsa_token}"
    return headers


async def _fetch_latest_semver_tag(client: httpx.AsyncClient) -> SemverTag | None:
    url = f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/tags?per_page=100"
    response = await request_with_retry(
        client,
        "GET",
        url,
        max_retries=2,
        backoff_base=2.0,
        log_prefix="version_check.tags",
        validate_json=True,
    )
    if response is None or response.status_code >= 400:
        log.warning(
            "version_check.tags_failed",
            status=getattr(response, "status_code", None),
        )
        return None
    try:
        payload = response.json()
    except ValueError:
        return None
    if not isinstance(payload, list) or not payload:
        return None
    best: tuple[tuple[int, int, int], str] | None = None
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        if not isinstance(name, str):
            continue
        parsed = _parse_semver(name)
        if parsed is None:
            continue
        if best is None or parsed > best[0]:
            best = (parsed, name)
    if best is None:
        return None
    tag = best[1]
    return SemverTag(tag=tag, release_url=f"{REPO_URL}/releases/tag/{tag}")


async def _fetch_latest_build_via_packages_api(
    client: httpx.AsyncClient, image: str
) -> LatestBuild | None:
    """Find the newest ``main-<sha>`` container tag for one image via the
    GitHub Packages API. Requires ``GHSA_TOKEN``. Returns ``None`` when no
    token is configured — caller falls back to anonymous GHCR.
    """
    if not settings.ghsa_token:
        return None
    owner = settings.hecate_ghcr_owner
    package_url = f"https://github.com/{owner}/hecate/pkgs/container/{image}"
    for scope in ("users", "orgs"):
        url = (
            f"https://api.github.com/{scope}/{owner}"
            f"/packages/container/{image}/versions?per_page=30"
        )
        response = await request_with_retry(
            client,
            "GET",
            url,
            max_retries=2,
            backoff_base=2.0,
            log_prefix=f"version_check.packages_{scope}",
            validate_json=True,
            context={"image": image},
        )
        if response is None or response.status_code == 404:
            continue
        if response.status_code >= 400:
            log.warning(
                "version_check.packages_failed",
                scope=scope,
                image=image,
                status=response.status_code,
            )
            continue
        try:
            payload = response.json()
        except ValueError:
            continue
        if not isinstance(payload, list):
            continue
        for entry in payload:
            if not isinstance(entry, dict):
                continue
            metadata = entry.get("metadata") or {}
            container = metadata.get("container") or {}
            tags = container.get("tags") or []
            if not isinstance(tags, list):
                continue
            for tag in tags:
                if not isinstance(tag, str):
                    continue
                match = _BUILD_TAG_RE.match(tag)
                if not match:
                    continue
                short_sha = _short_sha(match.group(1))
                published_at_raw = entry.get("updated_at") or entry.get("created_at")
                published_at: datetime | None = None
                if isinstance(published_at_raw, str) and published_at_raw:
                    try:
                        published_at = datetime.fromisoformat(
                            published_at_raw.replace("Z", "+00:00")
                        )
                    except ValueError:
                        published_at = None
                return LatestBuild(
                    tag=tag,
                    short_sha=short_sha,
                    published_at=published_at,
                    package_url=entry.get("html_url") or package_url,
                )
        log.info("version_check.no_build_tag", scope=scope, image=image)
        return None
    return None


async def _fetch_latest_build_via_anonymous_ghcr(
    client: httpx.AsyncClient, image: str
) -> LatestBuild | None:
    """Anonymous GHCR fallback. No timestamps; picks the last
    ``main-<sha>`` tag in the registry's tag list.
    """
    owner = settings.hecate_ghcr_owner
    package_url = f"https://github.com/{owner}/hecate/pkgs/container/{image}"
    token_url = (
        f"https://ghcr.io/token?service=ghcr.io"
        f"&scope=repository:{owner}/{image}:pull"
    )
    token_resp = await request_with_retry(
        client,
        "GET",
        token_url,
        max_retries=2,
        backoff_base=2.0,
        log_prefix="version_check.ghcr_token",
        validate_json=True,
        context={"image": image},
    )
    if token_resp is None or token_resp.status_code >= 400:
        log.warning(
            "version_check.ghcr_token_failed",
            image=image,
            status=getattr(token_resp, "status_code", None),
        )
        return None
    try:
        token = token_resp.json().get("token")
    except ValueError:
        return None
    if not isinstance(token, str) or not token:
        return None
    list_url = f"https://ghcr.io/v2/{owner}/{image}/tags/list"
    try:
        list_resp = await client.get(
            list_url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
            },
        )
    except httpx.HTTPError as exc:
        log.warning("version_check.ghcr_list_failed", image=image, error=str(exc))
        return None
    if list_resp.status_code >= 400:
        log.warning(
            "version_check.ghcr_list_failed",
            image=image,
            status=list_resp.status_code,
        )
        return None
    try:
        payload = list_resp.json()
    except ValueError:
        return None
    tags = payload.get("tags") if isinstance(payload, dict) else None
    if not isinstance(tags, list):
        return None
    candidates: list[tuple[str, str]] = []
    for tag in tags:
        if not isinstance(tag, str):
            continue
        match = _BUILD_TAG_RE.match(tag)
        if match:
            candidates.append((_short_sha(match.group(1)), tag))
    if not candidates:
        return None
    short_sha, tag = candidates[-1]
    return LatestBuild(
        tag=tag,
        short_sha=short_sha,
        published_at=None,
        package_url=package_url,
    )


async def _fetch_latest_build(
    client: httpx.AsyncClient, image: str
) -> LatestBuild | None:
    """Packages API first (timestamps, ordering), anonymous GHCR fallback."""
    primary = await _fetch_latest_build_via_packages_api(client, image)
    if primary is not None:
        return primary
    return await _fetch_latest_build_via_anonymous_ghcr(client, image)


# ---------------------------------------------------------------------------
# Aggregation + cache
# ---------------------------------------------------------------------------


_cache: dict[str, Any] = {"value": None, "expires_at": 0.0}
_cache_lock = asyncio.Lock()


async def _fetch_github_signals() -> dict[str, Any]:
    """Single round-trip per data source, all in parallel. Fail-open."""
    timeout = httpx.Timeout(10.0, connect=5.0)
    async with httpx.AsyncClient(
        verify=get_http_verify(), timeout=timeout, headers=_github_headers()
    ) as client:
        semver_task = asyncio.create_task(_fetch_latest_semver_tag(client))
        build_tasks = {
            comp: asyncio.create_task(_fetch_latest_build(client, image))
            for comp, image in COMPONENT_IMAGES.items()
        }
        semver = await semver_task
        builds = {comp: await task for comp, task in build_tasks.items()}
    return {"semver": semver, "builds": builds}


async def _get_cached_signals() -> dict[str, Any]:
    now = time.monotonic()
    cached = _cache["value"]
    if cached is not None and now < _cache["expires_at"]:
        return cached
    async with _cache_lock:
        now = time.monotonic()
        cached = _cache["value"]
        if cached is not None and now < _cache["expires_at"]:
            return cached
        signals = await _fetch_github_signals()
        _cache["value"] = signals
        _cache["expires_at"] = time.monotonic() + CACHE_TTL_SECONDS
        builds = signals.get("builds") or {}
        log.info(
            "version_check.cache_refreshed",
            has_semver=signals.get("semver") is not None,
            backend=builds.get("backend") is not None,
            frontend=builds.get("frontend") is not None,
            scanner=builds.get("scanner") is not None,
        )
        return signals


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


@router.get("/version")
async def get_version_info() -> VersionInfoResponse:
    """Per-component running build + latest GitHub signals (1 h cached).

    The backend self-reports its own SHA (file baked at image build time),
    probes the scanner sidecar over the compose network, and fans out three
    GHCR tag-list lookups in parallel. The frontend reports its own SHA
    via ``import.meta.env.VITE_BUILD_SHA`` baked into the bundle — the
    backend never sees it, the React app renders it directly. Update
    verdicts (per component) are computed client-side by comparing each
    running SHA to the matching ``ghcr.<component>.shortSha``.
    """
    # GitHub signals + scanner probe in parallel — independent.
    github_task = asyncio.create_task(_get_cached_signals())
    scanner_task = asyncio.create_task(_probe_scanner())
    signals = await github_task
    scanner_info = await scanner_task

    backend_info = RunningComponent(
        running_sha=_read_build_sha(),
        running_version=CURRENT_VERSION,
        reachable=True,
    )

    builds = signals.get("builds") or {}
    ghcr = GhcrLatest(
        backend=builds.get("backend"),
        frontend=builds.get("frontend"),
        scanner=builds.get("scanner"),
    )

    return VersionInfoResponse(
        backend=backend_info,
        scanner=scanner_info,
        ghcr=ghcr,
        semver_tag=signals.get("semver"),
        repo_url=REPO_URL,
        kofi_url=KOFI_URL,
        checked_at=datetime.now(UTC),
    )
