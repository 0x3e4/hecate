from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from dateutil import parser
import re
import structlog

from app.models.vulnerability import CvssScore, VulnerabilityDocument

log = structlog.get_logger()


def _parse_datetime(value: Any, *, fallback: datetime | None = None) -> datetime:
    if isinstance(value, datetime):
        return value.astimezone(UTC)
    if isinstance(value, str) and value:
        try:
            return parser.isoparse(value).astimezone(UTC)
        except (ValueError, TypeError):
            try:
                return parser.parse(value).astimezone(UTC)
            except (ValueError, TypeError):
                log.debug("normalizer.invalid_datetime", value=value)
    return (fallback or datetime.now(tz=UTC)).astimezone(UTC)


def _extract_cvss(data: dict[str, Any]) -> CvssScore:
    cvss_data = (
        data.get("cvss")
        or data.get("cvssv3")
        or data.get("cvssv2")
        or data.get("scores")
        or data.get("cvssScore")
        or {}
    )
    if isinstance(cvss_data, list) and cvss_data:
        cvss_data = cvss_data[0]
    if not isinstance(cvss_data, dict):
        cvss_data = {"base_score": data.get("score") or data.get("baseScore")}
        if "vector" not in cvss_data and data.get("vectorString"):
            cvss_data["vector"] = data.get("vectorString")
        if "severity" not in cvss_data and data.get("severity"):
            cvss_data["severity"] = data.get("severity")

    return CvssScore(
        version=cvss_data.get("version"),
        base_score=_safe_float(cvss_data.get("base_score") or cvss_data.get("baseScore")),
        vector=cvss_data.get("vector") or cvss_data.get("vectorString"),
        severity=_normalize_severity(cvss_data.get("severity") or cvss_data.get("baseSeverity")),
    )


def _safe_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _normalize_severity(value: Any) -> str | None:
    if isinstance(value, str):
        return value.lower()
    return None


def build_document(
    *,
    cve_id: str,
    source_id: str | None,
    euvd_record: dict[str, Any],
    supplemental_record: dict[str, Any] | None,
    ingested_at: datetime,
) -> VulnerabilityDocument:
    title = euvd_record.get("title") or euvd_record.get("summary") or cve_id
    summary = (
        euvd_record.get("summary")
        or euvd_record.get("description")
        or euvd_record.get("shortDescription")
        or ""
    )

    cwes = euvd_record.get("cwes") or euvd_record.get("cwe") or euvd_record.get("cweList") or []
    if isinstance(cwes, str):
        cwes = [cwes]
    elif isinstance(cwes, list):
        normalized_cwes: list[str] = []
        for entry in cwes:
            if isinstance(entry, str):
                normalized_cwes.append(entry)
            elif isinstance(entry, dict):
                code = entry.get("id") or entry.get("cwe")
                if isinstance(code, str):
                    normalized_cwes.append(code)
        cwes = normalized_cwes

    cpes = (
        euvd_record.get("cpes")
        or euvd_record.get("cpe")
        or euvd_record.get("cpeMatches")
        or euvd_record.get("cpeList")
        or []
    )
    if isinstance(cpes, str):
        cpes = [cpes]
    elif isinstance(cpes, list):
        normalized_cpes: list[str] = []
        for entry in cpes:
            if isinstance(entry, str):
                normalized_cpes.append(entry)
            elif isinstance(entry, dict):
                criteria = entry.get("criteria") or entry.get("cpe") or entry.get("matchCriteriaId")
                if isinstance(criteria, str):
                    normalized_cpes.append(criteria)
        cpes = normalized_cpes

    references = (
        euvd_record.get("references")
        or euvd_record.get("urls")
        or euvd_record.get("links")
        or []
    )
    if isinstance(references, list):
        normalized_refs: list[str] = []
        for ref in references:
            if isinstance(ref, str):
                normalized_refs.append(ref)
            elif isinstance(ref, dict):
                url = ref.get("url") or ref.get("link") or ref.get("href")
                if isinstance(url, str):
                    normalized_refs.append(url)
        references = normalized_refs
    elif isinstance(references, dict):
        references = [str(value) for value in references.values() if isinstance(value, str)]
    elif isinstance(references, str):
        references = [part.strip() for part in references.splitlines() if part.strip()]

    aliases = euvd_record.get("aliases") or euvd_record.get("alias") or []
    if isinstance(aliases, str):
        aliases = [part.strip() for part in aliases.splitlines() if part.strip()]
    elif isinstance(aliases, dict):
        aliases = [str(value).strip() for value in aliases.values() if isinstance(value, str)]
    elif isinstance(aliases, list):
        aliases = [str(value).strip() for value in aliases if isinstance(value, (str, int, float))]
    aliases = [alias for alias in aliases if alias]

    assigner = _ensure_str(euvd_record.get("assigner"))
    exploited = _to_optional_bool(euvd_record.get("exploited"))
    epss_score, epss_percentile = _parse_epss(euvd_record.get("epss"))

    vendors = _extract_vendors(euvd_record)
    products = _extract_products(euvd_record)

    published = _parse_datetime(
        euvd_record.get("published")
        or euvd_record.get("published_at")
        or euvd_record.get("publicationDate")
        or euvd_record.get("datePublished"),
        fallback=ingested_at,
    )
    modified = _parse_datetime(
        euvd_record.get("modified")
        or euvd_record.get("last_modified")
        or euvd_record.get("updatedDate")
        or euvd_record.get("lastModified"),
        fallback=published,
    )

    cvss = _extract_cvss(euvd_record)
    if not cvss.base_score and supplemental_record:
        nvd_metrics = (supplemental_record.get("cve") or {}).get("metrics") or {}
        if isinstance(nvd_metrics, dict):
            for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metrics = nvd_metrics.get(metric_key)
                if isinstance(metrics, list) and metrics:
                    cvss_details = metrics[0].get("cvssData") or metrics[0].get("cvssData")
                    if isinstance(cvss_details, dict):
                        cvss = CvssScore(
                            version=cvss_details.get("version"),
                            base_score=_safe_float(cvss_details.get("baseScore")),
                            vector=cvss_details.get("vectorString"),
                            severity=_normalize_severity(cvss_details.get("baseSeverity")),
                        )
                        break

    return VulnerabilityDocument(
        cve_id=cve_id,
        source_id=source_id,
        source=euvd_record.get("source", "EUVD"),
        title=title,
        summary=summary,
        references=[ref for ref in references if isinstance(ref, str)],
        cwes=[cwe for cwe in cwes if isinstance(cwe, str)],
        cpes=[cpe for cpe in cpes if isinstance(cpe, str)],
        aliases=[alias for alias in aliases if isinstance(alias, str)],
        assigner=assigner,
        exploited=exploited,
        epss_score=epss_score,
        epss_percentile=epss_percentile,
        vendors=vendors,
        products=products,
        cvss=cvss,
        published=published,
        modified=modified,
        ingested_at=ingested_at.astimezone(UTC),
        raw={"euvd": euvd_record, "supplemental": supplemental_record},
    )


def _ensure_str(value: Any) -> str | None:
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    return None


def _to_optional_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        value_lower = value.strip().lower()
        if value_lower in {"true", "yes", "1"}:
            return True
        if value_lower in {"false", "no", "0"}:
            return False
    return None


def _parse_epss(value: Any) -> tuple[float | None, float | None]:
    score: float | None = None
    percentile: float | None = None

    if isinstance(value, (int, float)):
        score = float(value)
    elif isinstance(value, str):
        numbers = [float(match) for match in re.findall(r"\d+(?:\.\d+)?", value)]
        if numbers:
            score = numbers[0]
            if len(numbers) > 1:
                percentile = numbers[1]
    elif isinstance(value, dict):
        raw_score = value.get("score") or value.get("epssScore")
        raw_percentile = value.get("percentile") or value.get("epssPercentile")
        score = _safe_float(raw_score)
        percentile = _safe_float(raw_percentile)

    return score, percentile


def _extract_vendors(record: dict[str, Any]) -> list[str]:
    vendors_raw = (
        record.get("vendors")
        or record.get("vendor")
        or record.get("enisaIdVendor")
        or []
    )

    names: list[str] = []
    seen: set[str] = set()

    def add_name(candidate: Any) -> None:
        if isinstance(candidate, str):
            trimmed = candidate.strip()
            if trimmed and trimmed not in seen:
                seen.add(trimmed)
                names.append(trimmed)

    if isinstance(vendors_raw, list):
        for entry in vendors_raw:
            if isinstance(entry, str):
                add_name(entry)
            elif isinstance(entry, dict):
                add_name(entry.get("name"))
                vendor_obj = entry.get("vendor")
                if isinstance(vendor_obj, dict):
                    add_name(vendor_obj.get("name"))
    elif isinstance(vendors_raw, dict):
        add_name(vendors_raw.get("name"))
    elif isinstance(vendors_raw, str):
        add_name(vendors_raw)

    return names


def _extract_products(record: dict[str, Any]) -> list[str]:
    products_raw = (
        record.get("products")
        or record.get("product")
        or record.get("enisaIdProduct")
        or []
    )

    products: list[str] = []
    seen_ids: set[str] = set()
    label_counts: dict[str, int] = {}

    def add_product(name: str | None, version: str | None = None, identifier: str | None = None) -> None:
        if not name:
            return
        label = name.strip()
        if not label:
            return
        version_clean = str(version).strip() if version else ""
        if version_clean:
            label = f"{label} ({version_clean})"

        if identifier:
            if identifier in seen_ids:
                return
            seen_ids.add(identifier)
        else:
            count = label_counts.get(label, 0)
            label_counts[label] = count + 1
            if count:
                label = f"{label} #{count + 1}"

        products.append(label)

    if isinstance(products_raw, list):
        for entry in products_raw:
            if isinstance(entry, str):
                add_product(entry)
            elif isinstance(entry, dict):
                version_hint = entry.get("product_version") or entry.get("version")
                entry_id = entry.get("id")
                if isinstance(entry.get("name"), str):
                    add_product(entry.get("name"), version_hint, entry_id)
                product_obj = entry.get("product")
                if isinstance(product_obj, dict):
                    add_product(
                        product_obj.get("name"),
                        product_obj.get("version")
                        or product_obj.get("product_version")
                        or version_hint,
                        entry_id or product_obj.get("id"),
                    )
    elif isinstance(products_raw, dict):
        add_product(
            products_raw.get("name"),
            products_raw.get("version") or products_raw.get("product_version"),
            products_raw.get("id"),
        )
    elif isinstance(products_raw, str):
        add_product(products_raw)

    return products


def _select_description(entries: Any, *, lang: str = "en") -> str | None:
    if isinstance(entries, list):
        for entry in entries:
            if isinstance(entry, dict):
                value = entry.get("value")
                entry_lang = str(entry.get("lang") or "").lower()
                if isinstance(value, str) and (not lang or entry_lang == lang.lower()):
                    return value
    return None


def _extract_cpes_from_nvd(record: dict[str, Any]) -> list[str]:
    cpes: list[str] = []
    configurations = record.get("configurations")
    if not isinstance(configurations, list):
        return cpes

    for configuration in configurations:
        if not isinstance(configuration, dict):
            continue
        nodes = configuration.get("nodes")
        if not isinstance(nodes, list):
            continue
        for node in nodes:
            if not isinstance(node, dict):
                continue
            matches = node.get("cpeMatch")
            if not isinstance(matches, list):
                continue
            for match in matches:
                if isinstance(match, dict) and match.get("vulnerable"):
                    criteria = match.get("criteria")
                    if isinstance(criteria, str):
                        cpes.append(criteria)
    return cpes


def _extract_cvss_from_nvd(metrics: Any) -> CvssScore:
    if not isinstance(metrics, dict):
        return CvssScore()

    for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(metric_key)
        if isinstance(metric_list, list) and metric_list:
            metric = metric_list[0]
            if isinstance(metric, dict):
                cvss_data = metric.get("cvssData")
                if isinstance(cvss_data, dict):
                    return CvssScore(
                        version=cvss_data.get("version"),
                        base_score=_safe_float(cvss_data.get("baseScore")),
                        vector=cvss_data.get("vectorString"),
                        severity=_normalize_severity(metric.get("baseSeverity")),
                    )
    return CvssScore()


def build_document_from_nvd(
    record: dict[str, Any],
    *,
    ingested_at: datetime,
) -> VulnerabilityDocument | None:
    if not isinstance(record, dict):
        return None
    cve_wrapper = record.get("cve")
    if not isinstance(cve_wrapper, dict):
        return None

    cve_id = cve_wrapper.get("id")
    if not isinstance(cve_id, str) or not cve_id.strip():
        return None

    description = _select_description(cve_wrapper.get("descriptions")) or ""
    title = description.split(".")[0] if description else cve_id
    summary = description or title

    references_raw = cve_wrapper.get("references") or []
    references: list[str] = []
    if isinstance(references_raw, list):
        for ref in references_raw:
            if isinstance(ref, dict):
                url = ref.get("url")
                if isinstance(url, str):
                    references.append(url)

    weaknesses = cve_wrapper.get("weaknesses") or []
    cwes: list[str] = []
    if isinstance(weaknesses, list):
        for weakness in weaknesses:
            if isinstance(weakness, dict):
                descriptions = weakness.get("description")
                value = _select_description(descriptions)
                if isinstance(value, str):
                    cwes.append(value)

    cpes = _extract_cpes_from_nvd(record)

    vendors: set[str] = set()
    products: set[str] = set()
    for cpe_uri in cpes:
        vendor = _parse_cpe_uri_component(cpe_uri, 3)
        product = _parse_cpe_uri_component(cpe_uri, 4)
        if vendor:
            vendors.add(vendor)
        if product:
            products.add(product)

    published = _parse_datetime(
        cve_wrapper.get("published"),
        fallback=ingested_at,
    )
    modified = _parse_datetime(
        cve_wrapper.get("lastModified"),
        fallback=published,
    )

    cvss = _extract_cvss_from_nvd(cve_wrapper.get("metrics"))

    document = VulnerabilityDocument(
        cve_id=cve_id,
        source_id=None,
        source="NVD",
        title=title,
        summary=summary,
        references=references,
        cwes=cwes,
        cpes=cpes,
        aliases=[],
        assigner=_ensure_str(cve_wrapper.get("sourceIdentifier")),
        exploited=None,
        epss_score=None,
        epss_percentile=None,
        vendors=sorted(vendors),
        products=sorted(products),
        cvss=cvss,
        published=published,
        modified=modified,
        ingested_at=ingested_at.astimezone(UTC),
        raw={"nvd": record},
    )
    return document
