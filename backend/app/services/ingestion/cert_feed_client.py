from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import UTC, datetime
from html import unescape
from html.parser import HTMLParser
from typing import Literal
from urllib.parse import urlsplit, urlunsplit
from xml.parsers import expat

import httpx
import structlog
from dateutil import parser as date_parser

from app.core.config import settings
from app.services.http.rate_limiter import AsyncRateLimiter
from app.services.http.public_host import is_public_url
from app.services.http.retry import request_with_retry
from app.services.http.ssl import get_http_verify

log = structlog.get_logger()

MAX_FEED_BYTES = 16 * 1024 * 1024
MAX_PAGE_BYTES = 4 * 1024 * 1024
MAX_TITLE_CHARS = 300
# A post without a title gets the start of its text instead (Mastodon writes no <title>).
FALLBACK_TITLE_CHARS = 160

FeedKind = Literal["cert", "vendor", "community"]
FEED_KINDS: tuple[str, ...] = ("cert", "vendor", "community")
DEFAULT_KIND: FeedKind = "cert"

_HYPHENS = "‐‑‒–—―"
_CVE_PATTERN = re.compile(rf"CVE[-{_HYPHENS}]\d{{4}}[-{_HYPHENS}]\d{{4,7}}", re.IGNORECASE)
_HYPHEN_TABLE = str.maketrans(dict.fromkeys(_HYPHENS, "-"))


@dataclass(frozen=True)
class CertFeed:
    """
    One advisory source. ``kind`` decides its weight: a CERT or a vendor counts as
    an independent voice, a community feed (a Mastodon account, a blog) is context.
    ``guard_host`` is set for feeds added through the UI, whose host is checked
    against private addresses before every fetch; ``.env`` feeds are trusted.
    """

    name: str
    url: str
    kind: str = DEFAULT_KIND
    guard_host: bool = False


@dataclass(frozen=True)
class CertAdvisoryItem:
    guid: str
    title: str
    url: str | None
    published: datetime | None
    cve_ids: list[str]


def extract_cve_ids(text: str) -> list[str]:
    return sorted({match.translate(_HYPHEN_TABLE).upper() for match in _CVE_PATTERN.findall(text)})


def safe_url(value: str | None) -> str | None:
    """A link from a feed ends up in an href, so only http(s) with a host gets through."""
    if not value:
        return None
    candidate = value.strip()
    try:
        parts = urlsplit(candidate)
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        return None
    return candidate


def parse_feed_config(*values: str) -> list[CertFeed]:
    """
    Reads comma-separated ``Name|URL`` or ``Name|URL|kind`` entries, ``kind`` being
    ``cert`` (the default), ``vendor`` or ``community``. A later entry with the same
    name replaces the earlier one.
    """
    feeds: dict[str, CertFeed] = {}
    for value in values:
        for entry in value.split(","):
            if not entry.strip():
                continue
            parts = [part.strip() for part in entry.split("|")]
            kind = parts[2].lower() if len(parts) == 3 else DEFAULT_KIND
            checked = safe_url(parts[1]) if len(parts) in (2, 3) else None
            if not parts[0] or not checked or kind not in FEED_KINDS:
                log.warning("cert_feed.invalid_config_entry", entry=entry.strip()[:120])
                continue
            feeds[parts[0]] = CertFeed(name=parts[0], url=checked, kind=kind)
    return list(feeds.values())


def merge_feeds(configured: list[CertFeed], managed: list[CertFeed]) -> list[CertFeed]:
    """``.env`` feeds first; a UI feed whose name a configured one already uses is skipped."""
    taken = {feed.name.casefold() for feed in configured}
    return [*configured, *(feed for feed in managed if feed.name.casefold() not in taken)]


class _TextCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        self.parts.append(data)


def plain_text(markup: str) -> str:
    """The visible text of an HTML fragment, whitespace collapsed."""
    collector = _TextCollector()
    collector.feed(markup)
    collector.close()
    return " ".join(unescape(" ".join(collector.parts)).split())


def _fallback_title(element: ET.Element) -> str:
    text = plain_text(_child_text(element, "description", "summary", "content", "encoded") or "")
    if len(text) <= FALLBACK_TITLE_CHARS:
        return text
    cut = text[:FALLBACK_TITLE_CHARS].rsplit(" ", 1)[0]
    return f"{cut}…"


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child_text(element: ET.Element, *names: str) -> str | None:
    for child in element:
        if _local_name(child.tag) in names and child.text and child.text.strip():
            return child.text.strip()
    return None


def _item_link(element: ET.Element) -> str | None:
    for child in element:
        if _local_name(child.tag) != "link":
            continue
        # Atom carries the target in an attribute and may list several links.
        if child.get("href") and child.get("rel", "alternate") == "alternate":
            return child.get("href")
        if child.text and child.text.strip():
            return child.text.strip()
    return None


def _parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = date_parser.parse(value, ignoretz=False)
    except (ValueError, OverflowError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _refuse_dtd(body: bytes) -> None:
    """
    Feeds are remote input: a DTD is how an entity bomb gets in, and no advisory
    feed needs one. The parser itself reports the declaration, so neither the
    encoding nor what precedes it can hide one, as a pattern over the bytes could.
    """

    def refuse(*_args: object) -> None:
        raise ValueError("feed declares a DTD")

    parser = expat.ParserCreate()
    parser.StartDoctypeDeclHandler = refuse
    parser.EntityDeclHandler = refuse
    try:
        parser.Parse(body, True)
    except expat.ExpatError as exc:
        raise ValueError(f"feed is not valid XML: {exc}") from exc


def parse_feed(content: bytes) -> list[CertAdvisoryItem]:
    """Parses RSS 2.0, RSS 1.0 (RDF) and Atom. Raises ``ValueError`` on anything else."""
    _refuse_dtd(content)
    try:
        root = ET.fromstring(content)
    except ET.ParseError as exc:
        raise ValueError(f"feed is not valid XML: {exc}") from exc

    items: list[CertAdvisoryItem] = []
    for element in root.iter():
        if _local_name(element.tag) not in ("item", "entry"):
            continue
        url = safe_url(_item_link(element))
        guid = _child_text(element, "guid", "id") or url
        if not guid:
            continue
        items.append(
            CertAdvisoryItem(
                guid=guid[:500],
                title=(_child_text(element, "title") or _fallback_title(element))[:MAX_TITLE_CHARS],
                url=url,
                published=_parse_date(_child_text(element, "pubDate", "published", "updated", "date")),
                cve_ids=extract_cve_ids(" ".join(element.itertext())),
            )
        )
    return items


def _bare_host(url: str) -> str:
    host = (urlsplit(url).hostname or "").lower()
    return host.removeprefix("www.")


class CertFeedClient:
    """Reads CERT advisory feeds. Fail-soft per feed: one broken source never stops the others."""

    def __init__(
        self,
        *,
        client: httpx.AsyncClient | None = None,
        rate_limiter: AsyncRateLimiter | None = None,
        max_retries: int | None = None,
        retry_backoff: float | None = None,
    ) -> None:
        # Redirects stay off: an advisory link must not be able to walk the backend onto another host.
        self._client = client or httpx.AsyncClient(
            timeout=httpx.Timeout(settings.cert_feeds_timeout_seconds, connect=10.0),
            headers={"User-Agent": settings.ingestion_user_agent},
            verify=get_http_verify(),
            follow_redirects=False,
        )
        self._rate_limiter = rate_limiter or AsyncRateLimiter(settings.cert_feeds_rate_limit_seconds)
        self._max_retries = settings.cert_feeds_max_retries if max_retries is None else max_retries
        self._retry_backoff = settings.cert_feeds_retry_backoff_seconds if retry_backoff is None else retry_backoff

    async def _get(self, url: str, *, feed: str) -> httpx.Response | None:
        return await request_with_retry(
            self._client,
            "GET",
            url,
            max_retries=self._max_retries,
            backoff_base=self._retry_backoff,
            log_prefix="cert_feed_client",
            rate_limiter=self._rate_limiter,
            context={"feed": feed},
        )

    async def fetch_feed(self, feed: CertFeed) -> list[CertAdvisoryItem] | None:
        """Returns the feed's items, or ``None`` when it could not be read."""
        if feed.guard_host and not settings.cert_feeds_allow_private_hosts and not await is_public_url(feed.url):
            log.warning("cert_feed.private_host_refused", feed=feed.name)
            return None
        response = await self._get(feed.url, feed=feed.name)
        if response is None or response.status_code != 200:
            log.warning(
                "cert_feed.fetch_failed",
                feed=feed.name,
                status=response.status_code if response is not None else None,
            )
            return None
        if len(response.content) > MAX_FEED_BYTES:
            log.warning("cert_feed.too_large", feed=feed.name, size=len(response.content))
            return None
        try:
            return parse_feed(response.content)
        except ValueError as exc:
            log.warning("cert_feed.parse_failed", feed=feed.name, error=str(exc))
            return None

    async def fetch_page_cves(self, feed: CertFeed, url: str) -> list[str] | None:
        """
        Reads the CVE IDs from an advisory's own page, for feeds that leave them out
        of the item. Only follows links on the feed's own host. ``None`` means the
        page could not be read and the item should be tried again on the next run.
        """
        if _bare_host(url) != _bare_host(feed.url):
            return []
        parts = urlsplit(url)
        page = urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))
        response = await self._get(page, feed=feed.name)
        if response is None or response.status_code >= 500:
            return None
        if response.status_code != 200 or len(response.content) > MAX_PAGE_BYTES:
            return []
        return extract_cve_ids(response.text)

    async def close(self) -> None:
        await self._client.aclose()
