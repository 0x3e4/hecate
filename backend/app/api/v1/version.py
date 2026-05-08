from __future__ import annotations

import asyncio
import re
import time
from datetime import UTC, datetime
from importlib import metadata as importlib_metadata
from pathlib import Path
from typing import Any, Literal

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

CACHE_TTL_SECONDS = 3600
_FALLBACK_VERSION = "1.0.0"
_SHORT_SHA_LEN = 7
_BUILD_SHA_FILE = Path("/app/.build_sha")
# Optional bind-mount targets the user can add to docker-compose.yml so the
# backend can self-detect its SHA when building locally (no CI build-arg
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


def _short_sha(value: str) -> str:
    return value.strip().lower()[:_SHORT_SHA_LEN]


def _read_sha_from_git_dir(git_dir: Path) -> str | None:
    """Parse ``.git/HEAD`` without invoking the git binary.

    Handles the two common shapes:

    * Detached HEAD: ``HEAD`` contains a 40-char SHA directly.
    * Branch HEAD: ``HEAD`` contains ``ref: refs/heads/<branch>`` and the
      SHA lives in ``.git/refs/heads/<branch>``.

    Packed refs (``.git/packed-refs``) and worktree gitfiles
    (``.git`` is a file, not a dir) are not handled — uncommon in a
    docker-compose deploy folder, and the user can fall back to setting
    ``HECATE_BUILD_SHA`` as an env var if needed.
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
    """Resolve the running build SHA.

    Resolution order:

    1. ``/app/.build_sha`` — file baked into the image at build time by CI
       (``--build-arg HECATE_BUILD_SHA=$GITHUB_SHA``). Using a file rather
       than an env var makes the value immune to docker-compose
       ``env_file`` overrides.
    2. ``/host/.git`` or ``/repo/.git`` — bind-mounted host git directory
       for users who run ``docker compose build`` locally and don't have
       access to a CI build-arg. One read-only volume mount and the
       indicator self-populates on every up.
    3. ``HECATE_BUILD_SHA`` env var — last resort for local dev runs that
       don't go through Docker at all (``poetry run uvicorn`` etc.).
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


def _running_short_sha() -> str | None:
    return _read_build_sha()


UpdateKind = Literal["semver", "build"] | None


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


class VersionInfoResponse(BaseModel):
    current_version: str = Field(alias="currentVersion", serialization_alias="currentVersion")
    current_sha: str | None = Field(
        default=None, alias="currentSha", serialization_alias="currentSha"
    )
    latest_version: str | None = Field(
        default=None, alias="latestVersion", serialization_alias="latestVersion"
    )
    latest_release_url: str | None = Field(
        default=None, alias="latestReleaseUrl", serialization_alias="latestReleaseUrl"
    )
    latest_build: LatestBuild | None = Field(
        default=None, alias="latestBuild", serialization_alias="latestBuild"
    )
    update_available: bool = Field(
        default=False, alias="updateAvailable", serialization_alias="updateAvailable"
    )
    update_kind: UpdateKind = Field(
        default=None, alias="updateKind", serialization_alias="updateKind"
    )
    repo_url: str = Field(alias="repoUrl", serialization_alias="repoUrl")
    kofi_url: str = Field(alias="kofiUrl", serialization_alias="kofiUrl")
    checked_at: UtcDatetime = Field(alias="checkedAt", serialization_alias="checkedAt")
    model_config = {"populate_by_name": True}


_cache: dict[str, Any] = {"value": None, "expires_at": 0.0}
_cache_lock = asyncio.Lock()


# ---------------------------------------------------------------------------
# Semver helpers
# ---------------------------------------------------------------------------


def _parse_semver(tag: str) -> tuple[int, int, int] | None:
    match = _SEMVER_TAG_RE.match(tag.strip())
    if not match:
        return None
    return (int(match.group(1)), int(match.group(2)), int(match.group(3) or "0"))


def _is_newer_semver(current: str, latest: str) -> bool:
    cur_t = _parse_semver(current)
    new_t = _parse_semver(latest)
    if cur_t is None or new_t is None:
        return current.lstrip("vV").strip() != latest.lstrip("vV").strip()
    return new_t > cur_t


# ---------------------------------------------------------------------------
# GitHub API calls
# ---------------------------------------------------------------------------


def _github_headers(*, accept: str = "application/vnd.github+json") -> dict[str, str]:
    headers = {
        "Accept": accept,
        "User-Agent": settings.ingestion_user_agent or "hecate-version-check",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if settings.ghsa_token:
        headers["Authorization"] = f"Bearer {settings.ghsa_token}"
    return headers


async def _fetch_latest_semver_tag(client: httpx.AsyncClient) -> dict[str, Any] | None:
    """Pick the highest semver-tagged ref from the public GitHub API.

    Sends ``Authorization: Bearer $GHSA_TOKEN`` when configured.
    """
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
    return {"tag": tag, "html_url": f"{REPO_URL}/releases/tag/{tag}"}


async def _fetch_latest_build_via_packages_api(
    client: httpx.AsyncClient,
) -> dict[str, Any] | None:
    """Find the newest `main-<sha>` container tag via GitHub's Packages API.

    Requires ``GHSA_TOKEN`` (any GitHub PAT). Returns ``None`` when no token is
    configured — the caller falls back to anonymous GHCR registry queries.
    The Packages API is preferred because it ships ``updated_at`` timestamps
    and groups every tag by image digest, so we can pick the truly newest
    ``main-<sha>`` build instead of relying on tag ordering.
    """
    if not settings.ghsa_token:
        return None
    owner = settings.hecate_ghcr_owner
    image = settings.hecate_ghcr_image
    package_url = f"https://github.com/{owner}/hecate/pkgs/container/{image}"

    # Try /users/ first (personal accounts); on 404 fall back to /orgs/.
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
        )
        if response is None:
            continue
        if response.status_code == 404:
            continue
        if response.status_code >= 400:
            log.warning(
                "version_check.packages_failed",
                scope=scope,
                status=response.status_code,
            )
            continue
        try:
            payload = response.json()
        except ValueError:
            continue
        if not isinstance(payload, list):
            continue
        # Versions are returned newest-first by `updated_at`. Pick the first
        # entry that carries a `main-<sha>` tag.
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
                return {
                    "tag": tag,
                    "short_sha": short_sha,
                    "updated_at": entry.get("updated_at") or entry.get("created_at"),
                    "package_url": entry.get("html_url") or package_url,
                }
        # Got a 2xx but no main-<sha> tag found — stop here, the package
        # exists at this scope but has no rolling tags.
        log.info("version_check.no_build_tag", scope=scope)
        return None
    return None


async def _fetch_latest_build_via_anonymous_ghcr(
    client: httpx.AsyncClient,
) -> dict[str, Any] | None:
    """Anonymous fallback: hit ghcr.io v2 directly. No timestamps, so we
    pick the lexicographically last ``main-<sha>`` tag in the list. Less
    accurate than the Packages API but works without a PAT.
    """
    owner = settings.hecate_ghcr_owner
    image = settings.hecate_ghcr_image
    package_url = f"https://github.com/{owner}/hecate/pkgs/container/{image}"

    # Anonymous bearer-token flow for public packages.
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
    )
    if token_resp is None or token_resp.status_code >= 400:
        log.warning(
            "version_check.ghcr_token_failed",
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
    list_resp = await client.get(
        list_url,
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
    )
    if list_resp.status_code >= 400:
        log.warning("version_check.ghcr_list_failed", status=list_resp.status_code)
        return None
    try:
        payload = list_resp.json()
    except ValueError:
        return None
    tags = payload.get("tags") if isinstance(payload, dict) else None
    if not isinstance(tags, list):
        return None
    candidates: list[tuple[str, str]] = []  # (short_sha, full_tag)
    for tag in tags:
        if not isinstance(tag, str):
            continue
        match = _BUILD_TAG_RE.match(tag)
        if match:
            candidates.append((_short_sha(match.group(1)), tag))
    if not candidates:
        return None
    # No timestamps available. Pick the last entry — GHCR usually returns
    # tags in insertion order, so the most recent push lands last. This is
    # imperfect but the best signal we have without auth.
    short_sha, tag = candidates[-1]
    return {
        "tag": tag,
        "short_sha": short_sha,
        "updated_at": None,
        "package_url": package_url,
    }


async def _fetch_version_signals() -> dict[str, Any]:
    """One round-trip per data source, fail-open. Returns a partial dict —
    missing keys mean that signal is unavailable.
    """
    timeout = httpx.Timeout(10.0, connect=5.0)
    async with httpx.AsyncClient(
        verify=get_http_verify(), timeout=timeout, headers=_github_headers()
    ) as client:
        semver_task = asyncio.create_task(_fetch_latest_semver_tag(client))
        build_task = asyncio.create_task(_fetch_latest_build_via_packages_api(client))
        semver_release = await semver_task
        build_via_api = await build_task
        build = build_via_api
        if build is None:
            # No PAT or 404 — try the anonymous GHCR registry path as a fallback.
            build = await _fetch_latest_build_via_anonymous_ghcr(client)
    return {"semver": semver_release, "build": build}


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
        signals = await _fetch_version_signals()
        _cache["value"] = signals
        _cache["expires_at"] = time.monotonic() + CACHE_TTL_SECONDS
        log.info(
            "version_check.cache_refreshed",
            has_semver=signals.get("semver") is not None,
            has_build=signals.get("build") is not None,
        )
        return signals


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


@router.get("/version")
async def get_version_info() -> VersionInfoResponse:
    """Current Hecate version + latest GitHub signals (1 h cached, fail-open).

    Detection priority:

    1. **Semver git tag**: if a `vX.Y.Z` tag on the repo is newer than the
       running ``CURRENT_VERSION``, that's the canonical update signal.
    2. **GHCR rolling-build tag**: if the running container's
       ``HECATE_BUILD_SHA`` differs from the newest ``main-<sha>`` tag on
       ghcr.io, surface that as a build update. Only applies once the build
       arg is wired through CI; otherwise the field stays informational.
    """
    signals = await _get_cached_signals()
    semver = signals.get("semver")
    build = signals.get("build")

    latest_version = semver.get("tag") if semver else None
    latest_release_url = semver.get("html_url") if semver else None

    latest_build_model: LatestBuild | None = None
    if build:
        published_at_raw = build.get("updated_at")
        published_at: datetime | None = None
        if isinstance(published_at_raw, str) and published_at_raw:
            try:
                published_at = datetime.fromisoformat(
                    published_at_raw.replace("Z", "+00:00")
                )
            except ValueError:
                published_at = None
        latest_build_model = LatestBuild(
            tag=build["tag"],
            short_sha=build["short_sha"],
            published_at=published_at,
            package_url=build.get("package_url"),
        )

    running_sha = _running_short_sha()
    update_kind: UpdateKind = None
    if latest_version and _is_newer_semver(CURRENT_VERSION, latest_version):
        update_kind = "semver"
    elif (
        latest_build_model
        and running_sha
        and latest_build_model.short_sha != running_sha
    ):
        update_kind = "build"

    return VersionInfoResponse(
        current_version=CURRENT_VERSION,
        current_sha=running_sha,
        latest_version=latest_version,
        latest_release_url=latest_release_url,
        latest_build=latest_build_model,
        update_available=update_kind is not None,
        update_kind=update_kind,
        repo_url=REPO_URL,
        kofi_url=KOFI_URL,
        checked_at=datetime.now(UTC),
    )
