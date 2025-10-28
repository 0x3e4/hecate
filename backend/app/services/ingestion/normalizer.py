from __future__ import annotations

from datetime import UTC, datetime
import copy
import json
from typing import Any

from dateutil import parser
import re
import structlog

from app.models.vulnerability import CvssScore, VulnerabilityDocument

log = structlog.get_logger()

CVSS_METRIC_VERSION_PREFERENCE: tuple[tuple[str, str | None], ...] = (
    ("v40", "4.0"),
    ("v31", "3.1"),
    ("v30", "3.0"),
    ("v20", "2.0"),
    ("other", None),
)


def _parse_datetime(
    value: Any,
    *,
    fallback: datetime | None = None,
    allow_none: bool = False,
) -> datetime | None:
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
    if fallback is not None:
        return fallback.astimezone(UTC)
    if allow_none:
        return None
    return datetime.now(tz=UTC).astimezone(UTC)


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


def _normalize_decimal_string(value: Any) -> Any:
    if isinstance(value, str):
        candidate = value.replace(",", ".")
        match = re.search(r"-?\d+(?:\.\d+)?", candidate)
        if match:
            return match.group(0)
        return candidate.strip()
    return value


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
) -> tuple[VulnerabilityDocument, dict[str, set[str]]]:
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
    else:
        cwes = []
    cwes = [cwe for cwe in cwes if isinstance(cwe, str)]

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
    else:
        cpes = []
    cpes = [cpe for cpe in cpes if isinstance(cpe, str)]

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
    epss_score = _parse_epss(euvd_record.get("epss"))

    vendors = _extract_vendors(euvd_record)
    product_version_map = _extract_products(euvd_record)
    products = list(product_version_map.keys())
    product_versions = sorted({version for versions in product_version_map.values() for version in versions})

    published = _parse_datetime(
        euvd_record.get("published")
        or euvd_record.get("published_at")
        or euvd_record.get("publicationDate")
        or euvd_record.get("datePublished"),
        allow_none=True,
    )
    modified = _parse_datetime(
        euvd_record.get("modified")
        or euvd_record.get("last_modified")
        or euvd_record.get("lastModified")
        or euvd_record.get("updated")
        or euvd_record.get("updated_at")
        or euvd_record.get("updatedAt")
        or euvd_record.get("updatedDate")
        or euvd_record.get("dateUpdated")
        or euvd_record.get("modificationDate")
        or euvd_record.get("last_update")
        or euvd_record.get("lastUpdate")
        or euvd_record.get("last_update_date"),
        fallback=published,
        allow_none=True,
    )

    cvss = _extract_cvss(euvd_record)
    if not cvss.base_score and supplemental_record and isinstance(supplemental_record, dict):
        supplemental_metrics = ((supplemental_record.get("cve") or {}).get("metrics"))
        fallback_cvss = _extract_cvss_from_nvd(supplemental_metrics)
        if fallback_cvss.base_score:
            cvss = fallback_cvss

    cvss_metrics = _merge_cvss_metrics(
        _extract_cvss_metrics_from_euvd(euvd_record),
        _extract_cvss_metrics_from_nvd(supplemental_record),
    )

    cvss = apply_inferred_cvss(cvss, cvss_metrics)

    if supplemental_record:
        supplemental_cve = supplemental_record.get("cve") if isinstance(supplemental_record, dict) else None
        if isinstance(supplemental_cve, dict):
            supplemental_cwes = _extract_cwes_from_nvd(supplemental_cve)
            if supplemental_cwes:
                cwes = _merge_unique_strings(cwes, supplemental_cwes)
        supplemental_cpes = _extract_cpes_from_nvd(supplemental_record)
        if supplemental_cpes:
            cpes = _merge_unique_strings(cpes, supplemental_cpes)

    document = VulnerabilityDocument(
        vuln_id=cve_id,
        source_id=source_id,
        source=euvd_record.get("source", "EUVD"),
        title=title,
        summary=summary,
        references=[ref for ref in references if isinstance(ref, str)],
        cwes=_merge_unique_strings(cwes),
        cpes=_merge_unique_strings(cpes),
        aliases=[alias for alias in aliases if isinstance(alias, str)],
        rejected=_determine_rejected(euvd_record, supplemental_record),
        assigner=assigner,
        exploited=exploited,
        epss_score=epss_score,
        vendors=vendors,
        products=products,
        product_versions=product_versions,
        cvss=cvss,
        cvss_metrics=cvss_metrics,
        published=published,
        modified=modified,
        ingested_at=ingested_at.astimezone(UTC),
        raw={"euvd": euvd_record, "supplemental": supplemental_record},
    )
    return document, product_version_map


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


def _parse_epss(value: Any) -> float | None:
    raw: float | None = None

    if isinstance(value, (int, float)):
        raw = float(value)
    elif isinstance(value, str):
        normalized = value.replace(",", ".")
        numbers = [float(match) for match in re.findall(r"\d+(?:\.\d+)?", normalized)]
        if numbers:
            raw = numbers[0]
    elif isinstance(value, dict):
        candidate = value.get("score") or value.get("epssScore")
        raw = _safe_float(_normalize_decimal_string(candidate))

    if raw is None:
        return None

    if 0 < raw <= 1:
        raw *= 100
    return round(raw, 2)


def _merge_unique_strings(*value_lists: Any) -> list[str]:
    merged: list[str] = []
    seen: set[str] = set()
    for value_list in value_lists:
        if not value_list:
            continue
        for value in value_list:
            if isinstance(value, str) and value not in seen:
                seen.add(value)
                merged.append(value)
    return merged


def _canonical_metric_key(key: Any) -> str:
    if not isinstance(key, str):
        return "other"
    lowered = key.lower()
    if "v40" in lowered or lowered.endswith("v4"):
        return "v40"
    if "v30" in lowered:
        return "v30"
    if "v31" in lowered:
        return "v31"
    if "v3" in lowered:
        return "v31"
    if "v2" in lowered:
        return "v20"
    return "other"


def _prepare_cvss_metric_entry(entry: dict[str, Any]) -> dict[str, Any]:
    sanitized = copy.deepcopy(entry)
    data_source = sanitized.get("cvssData")
    if isinstance(data_source, dict):
        sanitized["data"] = copy.deepcopy(data_source)
    else:
        synthesized: dict[str, Any] = {}
        for field in (
            "version",
            "baseScore",
            "baseSeverity",
            "vectorString",
            "attackVector",
            "attackComplexity",
            "privilegesRequired",
            "userInteraction",
            "scope",
            "confidentialityImpact",
            "integrityImpact",
            "availabilityImpact",
        ):
            value = sanitized.get(field)
            if value is not None:
                synthesized[field] = value
        if synthesized:
            sanitized["data"] = synthesized
    sanitized.pop("cvssData", None)
    sanitized.pop("cvss_data", None)
    return sanitized


def _merge_cvss_metrics(*metric_sets: Any) -> dict[str, list[dict[str, Any]]]:
    canonical: dict[str, list[dict[str, Any]]] = {}
    seen: dict[str, set[str]] = {}
    for metric_set in metric_sets:
        if not isinstance(metric_set, dict):
            continue
        for key, entries in metric_set.items():
            if not isinstance(entries, list):
                continue
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                canonical_key = _canonical_metric_key(key)
                sanitized_entry = _prepare_cvss_metric_entry(entry)
                serialized = json.dumps(sanitized_entry, sort_keys=True, default=str)
                bucket = canonical.setdefault(canonical_key, [])
                bucket_seen = seen.setdefault(canonical_key, set())
                if serialized in bucket_seen:
                    continue
                bucket_seen.add(serialized)
                bucket.append(sanitized_entry)

    return {key: [copy.deepcopy(entry) for entry in entries] for key, entries in canonical.items()}


def _cvss_metric_key_from_version(version: Any) -> str | None:
    if isinstance(version, str):
        normalized = version.replace("CVSS:", "").strip()
        digits = normalized.replace(".", "")
        if digits:
            return _canonical_metric_key(f"cvssMetricV{digits}")
    return None


def _cvss_version_rank(value: Any) -> int:
    if isinstance(value, str):
        match = re.search(r"(\d)(?:\.(\d))?", value)
        if match:
            major = match.group(1)
            minor = match.group(2) or "0"
            try:
                return int(f"{major}{minor}")
            except ValueError:
                return -1
    return -1


def _extract_metric_fields(entry: dict[str, Any]) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    data = entry.get("data")
    if isinstance(data, dict):
        payload.update(data)
    for field in ("version", "baseScore", "baseSeverity", "severity", "vectorString", "vector"):
        if field not in payload and entry.get(field) is not None:
            payload[field] = entry[field]
    return payload


def _infer_cvss_from_metrics(metrics: dict[str, list[dict[str, Any]]]) -> CvssScore | None:
    if not isinstance(metrics, dict) or not metrics:
        return None

    for key, default_version in CVSS_METRIC_VERSION_PREFERENCE:
        entries = metrics.get(key)
        if not isinstance(entries, list) or not entries:
            continue

        best_entry: dict[str, Any] | None = None
        best_score: float | None = None

        for entry in entries:
            if not isinstance(entry, dict):
                continue
            fields = _extract_metric_fields(entry)
            score = _safe_float(fields.get("baseScore") or fields.get("score"))
            severity = fields.get("baseSeverity") or fields.get("severity")
            vector = fields.get("vectorString") or fields.get("vector")
            version = fields.get("version") or default_version

            if score is None and severity is None and vector is None:
                continue

            if best_entry is None or (
                score is not None
                and (best_score is None or score > best_score)
            ):
                best_entry = {
                    "version": version,
                    "base_score": score,
                    "vector": vector,
                    "severity": severity,
                }
                best_score = score if score is not None else best_score

        if best_entry is not None:
            return CvssScore(
                version=best_entry.get("version"),
                base_score=best_entry.get("base_score"),
                vector=best_entry.get("vector"),
                severity=_normalize_severity(best_entry.get("severity")),
            )

    return None


def apply_inferred_cvss(base: CvssScore, metrics: dict[str, list[dict[str, Any]]]) -> CvssScore:
    inferred = _infer_cvss_from_metrics(metrics)
    if inferred is None:
        return base

    current_rank = _cvss_version_rank(base.version)
    inferred_rank = _cvss_version_rank(inferred.version)

    adopt_base = False
    if base.base_score is None and inferred.base_score is not None:
        adopt_base = True
    elif inferred.base_score is not None and inferred_rank > current_rank:
        adopt_base = True

    base_score = inferred.base_score if adopt_base else base.base_score
    severity = (
        inferred.severity
        if adopt_base and inferred.severity is not None
        else (base.severity if base.severity is not None else inferred.severity)
    )
    vector = (
        inferred.vector
        if adopt_base and inferred.vector is not None
        else (base.vector if base.vector is not None else inferred.vector)
    )

    version = base.version
    if adopt_base and inferred.version:
        version = inferred.version
    elif not version and inferred.version:
        version = inferred.version

    return CvssScore(
        version=version,
        base_score=base_score,
        vector=vector,
        severity=severity,
    )


def _extract_cvss_metrics_from_euvd(record: Any) -> dict[str, list[dict[str, Any]]]:
    if not isinstance(record, dict):
        return {}

    collected: list[tuple[str | None, dict[str, Any]]] = []
    queue: list[dict[str, Any]] = [record]
    seen_ids: set[int] = set()

    while queue:
        current = queue.pop()
        if id(current) in seen_ids:
            continue
        seen_ids.add(id(current))

        version = current.get("baseScoreVersion") or current.get("cvssVersion") or current.get("version")
        vector = current.get("baseScoreVector") or current.get("vectorString") or current.get("vector")
        score = _safe_float(current.get("baseScore") or current.get("score"))
        severity = current.get("baseSeverity") or current.get("severity")
        source = current.get("assigner") or current.get("source")
        metric_type = current.get("type")

        entry: dict[str, Any] = {}
        if version:
            entry["version"] = version
        if score is not None:
            entry["baseScore"] = score
        if isinstance(vector, str):
            entry["vectorString"] = vector
        if severity:
            entry["baseSeverity"] = severity
        if isinstance(source, str) and source:
            entry["source"] = source
        if isinstance(metric_type, str) and metric_type:
            entry["type"] = metric_type
        if entry:
            collected.append((version if isinstance(version, str) else None, entry))

        scores = current.get("scores")
        if isinstance(scores, list):
            for candidate in scores:
                if isinstance(candidate, dict):
                    queue.append(candidate)

        nested_vulns = current.get("enisaIdVulnerability")
        if isinstance(nested_vulns, list):
            for candidate in nested_vulns:
                vulnerability = candidate.get("vulnerability") if isinstance(candidate, dict) else None
                if isinstance(vulnerability, dict):
                    queue.append(vulnerability)

    metrics: dict[str, list[dict[str, Any]]] = {}
    for version, entry in collected:
        key = _cvss_metric_key_from_version(version) or "other"
        metrics.setdefault(key, []).append(entry)

    return _merge_cvss_metrics(metrics)


def _extract_cvss_metrics_from_nvd(record: Any) -> dict[str, list[dict[str, Any]]]:
    if not isinstance(record, dict):
        return {}

    metrics_source: Any
    if "cve" in record and isinstance(record["cve"], dict):
        metrics_source = record["cve"].get("metrics")
    else:
        metrics_source = record.get("metrics")

    if not isinstance(metrics_source, dict):
        return {}

    cleaned: dict[str, list[dict[str, Any]]] = {}
    for key, entries in metrics_source.items():
        if not isinstance(entries, list):
            continue
        sanitized: list[dict[str, Any]] = []
        for entry in entries:
            if isinstance(entry, dict):
                sanitized.append(copy.deepcopy(entry))
        if sanitized:
            cleaned[key] = sanitized

    return _merge_cvss_metrics(cleaned)


def _determine_rejected(*records: Any) -> bool:
    def _value_signals_rejected(value: Any) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"rejected", "reject"}:
                return True
        return False

    def _text_signals_rejected(value: Any) -> bool:
        if isinstance(value, str):
            return "** REJECT" in value.upper()
        return False

    def _record_signals_rejected(record: Any, depth: int = 0) -> bool:
        if depth > 3 or not isinstance(record, dict):
            return False

        for key in ("rejected", "isRejected"):
            if key in record and _value_signals_rejected(record[key]):
                return True

        for key in ("status", "state", "vulnStatus", "vulnerabilityStatus"):
            candidate = record.get(key)
            if _value_signals_rejected(candidate):
                return True
            if isinstance(candidate, dict):
                for nested in candidate.values():
                    if _value_signals_rejected(nested):
                        return True

        for text_key in ("description", "summary", "shortDescription", "title", "notes", "message"):
            if _text_signals_rejected(record.get(text_key)):
                return True

        for nested_key in ("cve", "cveMetadata", "metadata", "details"):
            nested = record.get(nested_key)
            if isinstance(nested, dict) and _record_signals_rejected(nested, depth + 1):
                return True

        return False

    return any(_record_signals_rejected(record) for record in records if isinstance(record, dict))


def _extract_vendors(record: dict[str, Any]) -> list[str]:
    vendors_raw = (
        record.get("vendors")
        or record.get("vendor")
        or record.get("enisaIdVendor")
        or record.get("affectedVendors")
        or record.get("affected_vendors")
        or record.get("impactedVendors")
        or record.get("impacted_vendors")
        or record.get("vendorList")
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


def _extract_products(record: dict[str, Any]) -> dict[str, set[str]]:
    products_raw = (
        record.get("products")
        or record.get("product")
        or record.get("enisaIdProduct")
        or record.get("affectedProducts")
        or record.get("affected_products")
        or record.get("impactedProducts")
        or record.get("impacted_products")
        or record.get("productList")
        or []
    )

    products: dict[str, set[str]] = {}
    seen_entries: set[tuple[str, str | None]] = set()

    def add_product(name: str | None, version: str | None = None) -> None:
        if not name:
            return
        label = name.strip()
        if not label:
            return
        version_clean = _normalize_version(version)
        key = (label.lower(), version_clean)
        if key in seen_entries:
            return
        seen_entries.add(key)

        product_versions = products.setdefault(label, set())
        if version_clean:
            product_versions.add(version_clean)

    if isinstance(products_raw, list):
        for entry in products_raw:
            if isinstance(entry, str):
                add_product(entry)
            elif isinstance(entry, dict):
                version_hint = entry.get("product_version") or entry.get("version")
                if isinstance(entry.get("name"), str):
                    add_product(entry.get("name"), version_hint)
                product_obj = entry.get("product")
                if isinstance(product_obj, dict):
                    add_product(
                        product_obj.get("name"),
                        product_obj.get("version")
                        or product_obj.get("product_version")
                        or version_hint,
                    )
    elif isinstance(products_raw, dict):
        add_product(
            products_raw.get("name"),
            products_raw.get("version") or products_raw.get("product_version"),
        )
    elif isinstance(products_raw, str):
        add_product(products_raw)

    return products


def _normalize_version(value: str | None) -> str | None:
    if not value:
        return None
    normalized = str(value).strip()
    if not normalized or normalized in {"*", "-"}:
        return None
    return normalized


def _humanize_label(value: str | None) -> str | None:
    if not value:
        return None
    label = value.replace("_", " ").strip()
    return label or None


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
    configurations = record.get("configurations")
    if not isinstance(configurations, list):
        return []

    collected: list[str] = []

    def walk_nodes(nodes: list[Any]) -> None:
        for node in nodes:
            if not isinstance(node, dict):
                continue
            matches = node.get("cpeMatch")
            if isinstance(matches, list):
                for match in matches:
                    if not isinstance(match, dict):
                        continue
                    if match.get("vulnerable"):
                        criteria = match.get("criteria")
                        if isinstance(criteria, str):
                            collected.append(criteria)
                        else:
                            fallback = match.get("cpeName") or match.get("matchCriteriaId")
                            if isinstance(fallback, str):
                                collected.append(fallback)
            nested_nodes = node.get("nodes")
            if isinstance(nested_nodes, list):
                walk_nodes(nested_nodes)

    for configuration in configurations:
        if isinstance(configuration, dict):
            nodes = configuration.get("nodes")
            if isinstance(nodes, list):
                walk_nodes(nodes)

    return _merge_unique_strings(collected)


def _extract_cwes_from_nvd(cve_wrapper: dict[str, Any]) -> list[str]:
    if not isinstance(cve_wrapper, dict):
        return []

    weaknesses = cve_wrapper.get("weaknesses") or []
    if not isinstance(weaknesses, list):
        return []

    collected: list[str] = []
    for weakness in weaknesses:
        if not isinstance(weakness, dict):
            continue
        descriptions = weakness.get("description") or weakness.get("descriptions")
        if isinstance(descriptions, list):
            for entry in descriptions:
                if isinstance(entry, dict):
                    value = entry.get("value")
                    if isinstance(value, str):
                        collected.append(value)
        elif isinstance(descriptions, str):
            collected.append(descriptions)

    return _merge_unique_strings(collected)


def _extract_cvss_from_nvd(metrics: Any) -> CvssScore:
    if not isinstance(metrics, dict):
        return CvssScore()

    for metric_key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(metric_key)
        if isinstance(metric_list, list) and metric_list:
            metric = metric_list[0]
            if isinstance(metric, dict):
                cvss_data = metric.get("cvssData") or metric
                if isinstance(cvss_data, dict):
                    severity = (
                        cvss_data.get("baseSeverity")
                        or metric.get("baseSeverity")
                        or cvss_data.get("severity")
                        or metric.get("severity")
                    )
                    return CvssScore(
                        version=cvss_data.get("version"),
                        base_score=_safe_float(cvss_data.get("baseScore") or metric.get("baseScore")),
                        vector=cvss_data.get("vectorString") or metric.get("vectorString"),
                        severity=_normalize_severity(severity),
                    )
    return CvssScore()


def build_document_from_nvd(
    record: dict[str, Any],
    *,
    ingested_at: datetime,
) -> tuple[VulnerabilityDocument, dict[str, set[str]]] | None:
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

    cwes = _extract_cwes_from_nvd(cve_wrapper)

    cpes = _extract_cpes_from_nvd(record)

    vendors: set[str] = set()
    product_version_map: dict[str, set[str]] = {}
    for cpe_uri in cpes:
        vendor = _parse_cpe_uri_component(cpe_uri, 3)
        product = _parse_cpe_uri_component(cpe_uri, 4)
        version = _parse_cpe_uri_component(cpe_uri, 5)
        vendor_label = _humanize_label(vendor)
        product_label = _humanize_label(product)
        version_value = _normalize_version(version)
        if vendor_label:
            vendors.add(vendor_label)
        if product_label:
            product_versions = product_version_map.setdefault(product_label, set())
            if version_value:
                product_versions.add(version_value)

    published = _parse_datetime(
        cve_wrapper.get("published"),
        allow_none=True,
    )
    modified = _parse_datetime(
        cve_wrapper.get("lastModified"),
        fallback=published,
        allow_none=True,
    )

    cvss = _extract_cvss_from_nvd(cve_wrapper.get("metrics"))
    cvss_metrics = _extract_cvss_metrics_from_nvd(record)
    cvss = apply_inferred_cvss(cvss, cvss_metrics)

    document = VulnerabilityDocument(
        vuln_id=cve_id,
        source_id=cve_id,
        source="NVD",
        title=title,
        summary=summary,
        references=references,
        cwes=cwes,
        cpes=cpes,
        aliases=[],
        rejected=_determine_rejected(record, cve_wrapper),
        assigner=_ensure_str(cve_wrapper.get("sourceIdentifier")),
        exploited=None,
        epss_score=None,
        vendors=sorted(vendors),
        products=list(product_version_map.keys()),
        product_versions=sorted({version for versions in product_version_map.values() for version in versions}),
        cvss=cvss,
        cvss_metrics=cvss_metrics,
        published=published,
        modified=modified,
        ingested_at=ingested_at.astimezone(UTC),
        raw={"nvd": record},
    )
    return document, product_version_map
