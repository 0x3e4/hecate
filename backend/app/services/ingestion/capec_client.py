from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

import httpx
import structlog

from app.core.config import settings
from app.services.http.rate_limiter import AsyncRateLimiter
from app.services.http.ssl import get_http_verify

log = structlog.get_logger()

# CAPEC XML namespace
_NS = {"capec": "http://capec.mitre.org/capec-3"}


def _text(element: ET.Element | None) -> str:
    """Extract text content from an XML element, joining nested text nodes."""
    if element is None:
        return ""
    parts: list[str] = []
    # Collect all text, including from nested inline tags (e.g. <xhtml:p>)
    for text in element.itertext():
        stripped = text.strip()
        if stripped:
            parts.append(stripped)
    return " ".join(parts)


class CAPECClient:
    """
    Client for MITRE CAPEC data.

    Downloads and parses the CAPEC XML file since MITRE does not
    provide a dedicated CAPEC REST API.

    Source: https://capec.mitre.org/data/xml/capec_latest.xml
    """

    def __init__(
        self,
        client: httpx.AsyncClient | None = None,
        rate_limiter: AsyncRateLimiter | None = None,
    ) -> None:
        self._client = client or httpx.AsyncClient(
            timeout=settings.capec_timeout_seconds,
            headers={
                "User-Agent": settings.ingestion_user_agent,
                "Accept": "application/xml",
            },
            verify=get_http_verify(),
        )
        self._rate_limiter = rate_limiter or AsyncRateLimiter(1.0)

    async def fetch_all_attack_patterns(self) -> list[dict[str, Any]]:
        """
        Download and parse all CAPEC attack patterns from the XML feed.

        Returns:
            List of dicts with keys: ID, Name, Description, Related_Weaknesses
        """
        try:
            log.info("capec_client.downloading_xml", url=settings.capec_xml_url)
            async with self._rate_limiter.slot():
                response = await self._client.get(settings.capec_xml_url)
            response.raise_for_status()

            return self._parse_xml(response.content)
        except httpx.HTTPError as exc:
            log.error("capec_client.download_failed", error=str(exc))
            return []

    def _parse_xml(self, xml_bytes: bytes) -> list[dict[str, Any]]:
        """Parse CAPEC XML into a list of attack pattern dicts."""
        try:
            root = ET.fromstring(xml_bytes)  # noqa: S314
        except ET.ParseError as exc:
            log.error("capec_client.xml_parse_error", error=str(exc))
            return []

        results: list[dict[str, Any]] = []

        # Find all Attack_Pattern elements (try with and without namespace)
        patterns = root.findall(".//capec:Attack_Pattern", _NS)
        if not patterns:
            # Try without namespace
            patterns = root.findall(".//{http://capec.mitre.org/capec-3}Attack_Pattern")
        if not patterns:
            # Try plain (no namespace)
            patterns = root.findall(".//Attack_Pattern")

        for pattern in patterns:
            capec_id = pattern.get("ID", "")
            name = pattern.get("Name", "")
            status = pattern.get("Status", "")

            abstraction = pattern.get("Abstraction", "")

            if not capec_id or status == "Deprecated":
                continue

            # Extract description
            desc_el = pattern.find("capec:Description", _NS)
            if desc_el is None:
                desc_el = pattern.find("{http://capec.mitre.org/capec-3}Description")
            description = _text(desc_el)

            # Extract related CWE IDs
            related_cwes: list[str] = []
            weaknesses_el = pattern.find("capec:Related_Weaknesses", _NS)
            if weaknesses_el is None:
                weaknesses_el = pattern.find("{http://capec.mitre.org/capec-3}Related_Weaknesses")
            if weaknesses_el is not None:
                for rw in weaknesses_el:
                    cwe_id = rw.get("CWE_ID", "")
                    if cwe_id:
                        related_cwes.append(cwe_id)

            # Extract severity (Typical_Severity)
            severity_el = pattern.find("capec:Typical_Severity", _NS)
            if severity_el is None:
                severity_el = pattern.find("{http://capec.mitre.org/capec-3}Typical_Severity")
            severity = _text(severity_el)

            # Extract likelihood of attack
            likelihood_el = pattern.find("capec:Likelihood_Of_Attack", _NS)
            if likelihood_el is None:
                likelihood_el = pattern.find("{http://capec.mitre.org/capec-3}Likelihood_Of_Attack")
            likelihood = _text(likelihood_el)

            results.append({
                "ID": capec_id,
                "Name": name,
                "Status": status,
                "Abstraction": abstraction,
                "Description": description,
                "Related_Weaknesses": related_cwes,
                "Typical_Severity": severity,
                "Likelihood_Of_Attack": likelihood,
            })

        log.info("capec_client.parsed_attack_patterns", count=len(results))
        return results

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
