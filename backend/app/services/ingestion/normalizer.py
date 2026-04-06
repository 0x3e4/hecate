from __future__ import annotations

from datetime import UTC, datetime
import copy
import json
from typing import Any, Mapping

from dateutil import parser
import re
import structlog

from app.models.vulnerability import CvssScore, VulnerabilityDocument
from app.utils.strings import slugify

log = structlog.get_logger()

CVSS_METRIC_VERSION_PREFERENCE: tuple[tuple[str, str | None], ...] = (
    ("v40", "4.0"),
    ("v31", "3.1"),
    ("v30", "3.0"),
    ("v20", "2.0"),
    ("other", None),
)

_GHSA_ADVISORY_URL = re.compile(
    r"https?://github\.com/advisories/(GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})",
    re.IGNORECASE,
)


def extract_ghsa_ids(references: list[str]) -> list[str]:
    """Extract unique GHSA IDs from direct GitHub advisory URLs only."""
    ghsa_ids: list[str] = []
    for ref in references:
        if not isinstance(ref, str):
            continue
        m = _GHSA_ADVISORY_URL.match(ref)
        if m:
            ghsa_id = m.group(1).upper()
            if ghsa_id not in ghsa_ids:
                ghsa_ids.append(ghsa_id)
    return ghsa_ids


def _parse_cvss_vector_string(vector_string: str) -> dict[str, str]:
    """
    Parse a CVSS vector string and extract individual metrics.

    Examples:
        CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N
        CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P
        CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N

    Returns:
        Dictionary with metric keys and values
    """
    if not isinstance(vector_string, str):
        return {}

    metrics: dict[str, str] = {}

    # Split by / and process each metric
    parts = vector_string.split("/")

    # First part should be CVSS:X.X
    if parts and parts[0].startswith("CVSS:"):
        version = parts[0].replace("CVSS:", "").strip()
        metrics["version"] = version
        parts = parts[1:]  # Remove the version part

    # Parse the rest of the metrics
    for part in parts:
        if ":" not in part:
            continue
        key, value = part.split(":", 1)
        key = key.strip()
        value = value.strip()

        # Map short keys to full metric names
        # CVSS v3.x and v2.0 metrics
        # Note: Some keys are version-dependent and will be resolved based on context
        key_mapping = {
            # CVSS v3.x Base Metrics
            "AV": "attackVector",
            "AC": "attackComplexity",
            "PR": "privilegesRequired",
            "UI": "userInteraction",
            "S": "scope",  # CVSS 3.x - in 4.0 this can also mean "safety"
            "C": "confidentialityImpact",
            "I": "integrityImpact",
            "A": "availabilityImpact",
            # CVSS v2.0 Base Metrics
            "Au": "authentication",
            # CVSS v3.x Temporal Metrics
            "E": "exploitCodeMaturity",
            "RL": "remediationLevel",
            "RC": "reportConfidence",
            # CVSS v3.x Environmental Metrics
            "CR": "confidentialityRequirement",
            "IR": "integrityRequirement",
            "AR": "availabilityRequirement",
            "MAV": "modifiedAttackVector",
            "MAC": "modifiedAttackComplexity",
            "MPR": "modifiedPrivilegesRequired",
            "MUI": "modifiedUserInteraction",
            "MS": "modifiedScope",
            "MC": "modifiedConfidentialityImpact",
            "MI": "modifiedIntegrityImpact",
            "MA": "modifiedAvailabilityImpact",
            # CVSS v4.0 Base Metrics
            "AT": "attackRequirements",
            "VC": "vulnConfidentialityImpact",
            "VI": "vulnIntegrityImpact",
            "VA": "vulnAvailabilityImpact",
            "SC": "subConfidentialityImpact",
            "SI": "subIntegrityImpact",
            "SA": "subAvailabilityImpact",
            # CVSS v4.0 Threat Metrics
            "AU": "automatable",
            # CVSS v4.0 Environmental Metrics
            "R": "recovery",
            "V": "valueDensity",
            "RE": "vulnerabilityResponseEffort",
            "U": "providerUrgency",
            # CVSS v4.0 Supplemental Metrics (S is handled differently for v4)
            "MSI": "modifiedSubIntegrityImpact",
            "MSA": "modifiedSubAvailabilityImpact",
            "MSC": "modifiedSubConfidentialityImpact",
        }

        # Map values to full names
        value_mapping = {
            # Attack Vector
            "N": "NETWORK",
            "A": "ADJACENT_NETWORK",
            "L": "LOCAL",
            "P": "PHYSICAL",
            # Attack Complexity
            "L": "LOW",
            "H": "HIGH",
            # Privileges Required / Authentication
            "N": "NONE",
            "L": "LOW",
            "H": "HIGH",
            "M": "MULTIPLE",
            "S": "SINGLE",
            # User Interaction
            "N": "NONE",
            "R": "REQUIRED",
            "A": "ACTIVE",
            "P": "PASSIVE",
            # Scope
            "U": "UNCHANGED",
            "C": "CHANGED",
            # Impact metrics
            "N": "NONE",
            "L": "LOW",
            "H": "HIGH",
            # Exploit Code Maturity
            "X": "NOT_DEFINED",
            "U": "UNPROVEN",
            "P": "PROOF_OF_CONCEPT",
            "F": "FUNCTIONAL",
            "H": "HIGH",
            # Remediation Level
            "X": "NOT_DEFINED",
            "O": "OFFICIAL_FIX",
            "T": "TEMPORARY_FIX",
            "W": "WORKAROUND",
            "U": "UNAVAILABLE",
            # Report Confidence
            "X": "NOT_DEFINED",
            "U": "UNKNOWN",
            "R": "REASONABLE",
            "C": "CONFIRMED",
            # Requirements
            "X": "NOT_DEFINED",
            "L": "LOW",
            "M": "MEDIUM",
            "H": "HIGH",
        }

        full_key = key_mapping.get(key, key.lower())

        # Context-aware value mapping based on the metric type
        value_upper = value.upper()

        # Map values based on the specific metric context
        if full_key == "attackVector":
            av_map = {"N": "NETWORK", "A": "ADJACENT_NETWORK", "L": "LOCAL", "P": "PHYSICAL"}
            full_value = av_map.get(value_upper, value)
        elif full_key == "attackComplexity":
            ac_map = {"L": "LOW", "H": "HIGH"}
            full_value = ac_map.get(value_upper, value)
        elif full_key in ["privilegesRequired", "authentication"]:
            pr_map = {"N": "NONE", "L": "LOW", "H": "HIGH", "M": "MULTIPLE", "S": "SINGLE"}
            full_value = pr_map.get(value_upper, value)
        elif full_key == "userInteraction":
            ui_map = {"N": "NONE", "R": "REQUIRED", "A": "ACTIVE", "P": "PASSIVE"}
            full_value = ui_map.get(value_upper, value)
        elif full_key == "scope":
            s_map = {"U": "UNCHANGED", "C": "CHANGED"}
            full_value = s_map.get(value_upper, value)
        elif full_key in ["confidentialityImpact", "integrityImpact", "availabilityImpact",
                          "vulnConfidentialityImpact", "vulnIntegrityImpact", "vulnAvailabilityImpact",
                          "subConfidentialityImpact", "subIntegrityImpact", "subAvailabilityImpact",
                          "modifiedConfidentialityImpact", "modifiedIntegrityImpact", "modifiedAvailabilityImpact",
                          "modifiedSubConfidentialityImpact", "modifiedSubIntegrityImpact", "modifiedSubAvailabilityImpact"]:
            impact_map = {"N": "NONE", "L": "LOW", "H": "HIGH", "P": "PARTIAL", "C": "COMPLETE"}
            full_value = impact_map.get(value_upper, value)
        elif full_key == "exploitCodeMaturity":
            e_map = {"X": "NOT_DEFINED", "U": "UNPROVEN", "P": "PROOF_OF_CONCEPT", "F": "FUNCTIONAL", "H": "HIGH"}
            full_value = e_map.get(value_upper, value)
        elif full_key == "remediationLevel":
            rl_map = {"X": "NOT_DEFINED", "O": "OFFICIAL_FIX", "T": "TEMPORARY_FIX", "W": "WORKAROUND", "U": "UNAVAILABLE"}
            full_value = rl_map.get(value_upper, value)
        elif full_key == "reportConfidence":
            rc_map = {"X": "NOT_DEFINED", "U": "UNKNOWN", "R": "REASONABLE", "C": "CONFIRMED"}
            full_value = rc_map.get(value_upper, value)
        elif full_key in ["confidentialityRequirement", "integrityRequirement", "availabilityRequirement"]:
            req_map = {"X": "NOT_DEFINED", "L": "LOW", "M": "MEDIUM", "H": "HIGH"}
            full_value = req_map.get(value_upper, value)
        else:
            # Try generic mapping, otherwise keep as-is
            full_value = value_mapping.get(value_upper, value)

        metrics[full_key] = full_value

    return metrics


def _parse_datetime(
    value: Any,
    *,
    fallback: datetime | None = None,
    allow_none: bool = False,
) -> datetime | None:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)
    if isinstance(value, str) and value:
        try:
            dt = parser.isoparse(value)
            if dt.tzinfo is None:
                return dt.replace(tzinfo=UTC)
            return dt.astimezone(UTC)
        except (ValueError, TypeError):
            try:
                dt = parser.parse(value)
                if dt.tzinfo is None:
                    return dt.replace(tzinfo=UTC)
                return dt.astimezone(UTC)
            except (ValueError, TypeError):
                log.debug("normalizer.invalid_datetime", value=value)
    if fallback is not None:
        if fallback.tzinfo is None:
            return fallback.replace(tzinfo=UTC)
        return fallback.astimezone(UTC)
    if allow_none:
        return None
    return datetime.now(tz=UTC)


def _extract_cvss(data: dict[str, Any]) -> CvssScore:
    cvss_data = (
        data.get("cvss")
        or data.get("cvssv3")
        or data.get("cvssv2")
        or data.get("scores")
        or data.get("cvssScore")
    )
    if isinstance(cvss_data, list) and cvss_data:
        cvss_data = cvss_data[0]

    # If no cvss_data found, or it's an empty dict, check for EUVD flat format
    if not cvss_data or (isinstance(cvss_data, dict) and not cvss_data):
        # Handle EUVD format with baseScore, baseScoreVersion, baseScoreVector at top level
        if data.get("baseScore") is not None or data.get("score") is not None:
            cvss_data = {
                "base_score": data.get("score") or data.get("baseScore"),
                "version": data.get("baseScoreVersion"),
                "vector": data.get("baseScoreVector") or data.get("vectorString"),
                "severity": data.get("baseSeverity") or data.get("severity"),
            }
        else:
            cvss_data = {}

    version = cvss_data.get("version") or cvss_data.get("baseScoreVersion")
    base_score = _safe_float(cvss_data.get("base_score") or cvss_data.get("baseScore"))
    vector = cvss_data.get("vector") or cvss_data.get("vectorString") or cvss_data.get("baseScoreVector")
    severity = _normalize_severity(cvss_data.get("severity") or cvss_data.get("baseSeverity"))

    # Infer severity from score if not provided (common for EUVD records)
    if not severity and base_score is not None:
        severity = _infer_severity_from_score(base_score, version)

    return CvssScore(
        version=version,
        base_score=base_score,
        vector=vector,
        severity=severity,
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


def _infer_severity_from_score(score: float | None, version: str | None = None) -> str | None:
    """
    Infer CVSS severity rating from base score based on CVSS specification.

    CVSS v3.x:
    - None: 0.0
    - Low: 0.1-3.9
    - Medium: 4.0-6.9
    - High: 7.0-8.9
    - Critical: 9.0-10.0

    CVSS v2.0:
    - Low: 0.0-3.9
    - Medium: 4.0-6.9
    - High: 7.0-10.0
    """
    if score is None:
        return None

    # Determine version
    is_v2 = version and ("2.0" in str(version) or "v2" in str(version).lower())

    if is_v2:
        # CVSS v2.0 severity ratings
        if score == 0.0:
            return "none"
        elif 0.1 <= score <= 3.9:
            return "low"
        elif 4.0 <= score <= 6.9:
            return "medium"
        elif 7.0 <= score <= 10.0:
            return "high"
    else:
        # CVSS v3.x severity ratings (default)
        if score == 0.0:
            return "none"
        elif 0.1 <= score <= 3.9:
            return "low"
        elif 4.0 <= score <= 6.9:
            return "medium"
        elif 7.0 <= score <= 8.9:
            return "high"
        elif 9.0 <= score <= 10.0:
            return "critical"

    return None


def build_document(
    *,
    cve_id: str,
    source_id: str | None,
    euvd_record: dict[str, Any],
    supplemental_record: dict[str, Any] | None,
    supplemental_cpe_matches: list[dict[str, Any]] | None = None,
    ingested_at: datetime,
) -> tuple[VulnerabilityDocument, dict[str, set[str]]]:
    # Title should be the CVE ID or EUVD ID, not the description
    title = cve_id  # CVE ID if available, otherwise EUVD ID

    # Summary should prioritize NVD description, then EUVD description
    nvd_description = None
    if supplemental_record and isinstance(supplemental_record, dict):
        supplemental_cve = supplemental_record.get("cve")
        if isinstance(supplemental_cve, dict):
            nvd_description = _select_description(supplemental_cve.get("descriptions"))

    summary = (
        nvd_description
        or euvd_record.get("description")
        or euvd_record.get("summary")
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
    cpe_configurations: list[dict[str, Any]] = []
    cpe_version_tokens: list[str] = []
    impacted_products: list[dict[str, Any]] = []

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
    # Normalize GHSA/MAL/PYSEC aliases to uppercase for consistency
    aliases = [a.upper() if a.upper().startswith(("GHSA-", "MAL-", "PYSEC-")) else a for a in aliases]
    # Deduplicate after normalization
    seen: set[str] = set()
    deduped: list[str] = []
    for a in aliases:
        if a not in seen:
            seen.add(a)
            deduped.append(a)
    aliases = deduped
    # Add the EUVD source ID to aliases if present and not already included
    if source_id and source_id not in aliases and source_id != cve_id:
        aliases.append(source_id)
    # Extract GHSA IDs from references and add as aliases
    for ghsa_id in extract_ghsa_ids(references):
        if ghsa_id not in aliases:
            aliases.append(ghsa_id)

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

    if supplemental_cpe_matches:
        cpematch_configurations, cpematch_cpes, cpematch_tokens = _collect_cpe_data_from_cpematch(
            supplemental_cpe_matches
        )
        if cpematch_configurations:
            cpe_configurations = _merge_configuration_sets(cpe_configurations, cpematch_configurations)
        if cpematch_cpes:
            cpes = _merge_unique_strings(cpes, cpematch_cpes)
        if cpematch_tokens:
            cpe_version_tokens = _merge_unique_strings(cpe_version_tokens, cpematch_tokens)

    if supplemental_record:
        supplemental_cve = supplemental_record.get("cve") if isinstance(supplemental_record, dict) else None
        if isinstance(supplemental_cve, dict):
            supplemental_cwes = _extract_cwes_from_nvd(supplemental_cve)
            if supplemental_cwes:
                cwes = _merge_unique_strings(cwes, supplemental_cwes)
        supplemental_configurations, supplemental_cpes, supplemental_tokens = _collect_cpe_data_from_nvd(
            supplemental_record
        )
        if supplemental_configurations:
            cpe_configurations = _merge_configuration_sets(cpe_configurations, supplemental_configurations)
        if supplemental_cpes:
            cpes = _merge_unique_strings(cpes, supplemental_cpes)
        if supplemental_tokens:
            cpe_version_tokens = _merge_unique_strings(cpe_version_tokens, supplemental_tokens)

    if cpes:
        cpe_version_tokens = _merge_unique_strings(cpe_version_tokens, _tokens_from_cpes(cpes))

    if cve_id and "2024-57254" in cve_id:
        log.debug(
            "normalizer.before_building_document",
            vuln_id=cve_id,
            cpe_configurations_count=len(cpe_configurations),
            cpe_configurations_type=type(cpe_configurations).__name__,
            first_config_keys=list(cpe_configurations[0].keys()) if cpe_configurations else [],
        )

    impacted_products = _build_impacted_products_payload(
        cpe_configurations=cpe_configurations,
        cpematch_entries=supplemental_cpe_matches,
        cpes=cpes,
    )

    raw_payload: dict[str, Any] = {"euvd": euvd_record}
    if supplemental_record is not None:
        raw_payload["supplemental"] = supplemental_record
    if supplemental_cpe_matches:
        raw_payload["supplementalCpeMatches"] = supplemental_cpe_matches

    # Store cpe_configurations as raw dicts - bypass Pydantic validation
    # Pydantic will validate when possible but won't drop data on validation errors
    document = VulnerabilityDocument.model_construct(
        vuln_id=cve_id,
        source_id=source_id,
        source=euvd_record.get("source", "EUVD"),
        title=title,
        summary=summary,
        references=[ref for ref in references if isinstance(ref, str)],
        cwes=_merge_unique_strings(cwes),
        cpes=_merge_unique_strings(cpes),
        cpe_configurations=cpe_configurations,  # Pass dicts directly
        cpe_version_tokens=_merge_unique_strings(cpe_version_tokens),
        impacted_products=impacted_products,
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
        raw=raw_payload,
    )

    if cve_id and "2024-57254" in cve_id:
        log.debug(
            "normalizer.document_built",
            vuln_id=cve_id,
            cpe_configurations_count_before_constructor=len(cpe_configurations),
            document_cpe_configurations_count=len(document.cpe_configurations),
            impacted_products_count=len(impacted_products),
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

    # EPSS scores are typically in range 0-1 (e.g., 0.8 = 80%)
    # Store as-is without conversion
    return round(raw, 4)


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


def _merge_configuration_sets(
    base: list[dict[str, Any]] | None,
    additional: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    seen: set[str] = set()

    def append_unique(candidate: dict[str, Any]) -> None:
        serialized = json.dumps(candidate, sort_keys=True, default=str)
        if serialized not in seen:
            seen.add(serialized)
            merged.append(copy.deepcopy(candidate))

    for bucket in (base, additional):
        if not bucket:
            continue
        for entry in bucket:
            if isinstance(entry, dict):
                append_unique(entry)

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

        # Infer severity from score if not provided (common for EUVD records)
        if not severity and score is not None:
            severity = _infer_severity_from_score(score, version)

        entry: dict[str, Any] = {}
        if version:
            entry["version"] = version
        if score is not None:
            entry["baseScore"] = score
        if isinstance(vector, str):
            entry["vectorString"] = vector
            # Parse the vector string to extract individual metrics
            parsed_metrics = _parse_cvss_vector_string(vector)
            # Add the parsed metrics to the entry
            for metric_key, metric_value in parsed_metrics.items():
                if metric_key != "version" and metric_key not in entry:
                    entry[metric_key] = metric_value
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


def _normalize_token_component(value: str | None) -> str | None:
    if not value:
        return None
    normalized = value.strip().lower()
    if not normalized:
        return None
    normalized = normalized.replace(" ", "_")
    return normalized or None


def _normalize_cpe_component(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = value.replace("\\", "").strip()
    if not cleaned or cleaned in {"*", "-"}:
        return None
    return cleaned


def _parse_cpe_uri_details(value: str | None) -> dict[str, str | None]:
    if not isinstance(value, str):
        return {}
    candidate = value.strip()
    if not candidate or ":" not in candidate:
        return {}

    parts = candidate.split(":")
    if len(parts) < 13:
        parts.extend([""] * (13 - len(parts)))

    part = _normalize_cpe_component(parts[2] if len(parts) > 2 else None)
    vendor_raw = _normalize_cpe_component(parts[3] if len(parts) > 3 else None)
    product_raw = _normalize_cpe_component(parts[4] if len(parts) > 4 else None)
    version = _normalize_cpe_component(parts[5] if len(parts) > 5 else None)
    target_sw = _normalize_cpe_component(parts[10] if len(parts) > 10 else None)
    target_hw = _normalize_cpe_component(parts[11] if len(parts) > 11 else None)

    vendor = _humanize_label(vendor_raw) or vendor_raw
    product = _humanize_label(product_raw) or product_raw

    return {
        "part": part,
        "vendor_raw": vendor_raw,
        "vendor": vendor,
        "product_raw": product_raw,
        "product": product,
        "version": _normalize_version(version),
        "target_sw": target_sw,
        "target_hw": target_hw,
    }


def _parse_cpe_uri_component(cpe_uri: str | None, index: int) -> str | None:
    if not isinstance(cpe_uri, str):
        return None
    parsed = _parse_cpe_uri_details(cpe_uri)
    if index == 2:
        return parsed.get("part")
    if index == 3:
        return parsed.get("vendor_raw") or parsed.get("vendor")
    if index == 4:
        return parsed.get("product_raw") or parsed.get("product")
    if index == 5:
        return parsed.get("version")
    if index == 10:
        return parsed.get("target_sw")
    if index == 11:
        return parsed.get("target_hw")
    return None


def _decompose_version_variants(value: str | None) -> set[str]:
    if not value:
        return set()
    candidate = value.strip()
    if not candidate:
        return set()

    tokens: set[str] = {candidate.lower()}
    parts = re.split(r"[._-]", candidate)
    numeric_parts: list[str] = []
    for part in parts:
        if not part:
            continue
        if not part.isdigit():
            break
        numeric_parts.append(str(int(part)))
    progressive: list[str] = []
    for part in numeric_parts:
        progressive.append(part)
        tokens.add(".".join(progressive).lower())
    return {token for token in tokens if token}


def _build_version_tokens(
    vendor: str | None,
    product: str | None,
    version: str | None,
    start_inc: str | None,
    start_exc: str | None,
    end_inc: str | None,
    end_exc: str | None,
) -> set[str]:
    tokens: set[str] = set()
    values = [
        value
        for value in (version, start_inc, start_exc, end_inc, end_exc)
        if isinstance(value, str) and value.strip()
    ]
    if not values:
        return tokens

    vendor_component = _normalize_token_component(vendor)
    product_component = _normalize_token_component(product)

    for value in values:
        variants = _decompose_version_variants(value)
        if not variants:
            variants = {value.strip().lower()}
        tokens.update(variants)
        if product_component:
            tokens.update(f"{product_component}::{variant}" for variant in variants)
        if vendor_component and product_component:
            tokens.update(f"{vendor_component}::{product_component}::{variant}" for variant in variants)

    return {token for token in tokens if token}


def _encode_version_numeric(value: str | None) -> int | None:
    """Encode a semantic version string to a single integer for range comparisons.

    Uses base-10000 encoding to fit within MongoDB's 8-byte signed integer limit (2^63-1).
    Formula: v1 * 10000^3 + v2 * 10000^2 + v3 * 10000 + v4

    Max encoded value: 9999.9999.9999.9999 -> 9,999,999,999,999,999
    MongoDB limit: 9,223,372,036,854,775,807 (2^63-1)

    Version components > 9999 will be capped at 9999.

    Args:
        value: Version string (e.g., "1.2.3", "2.0.0-beta")

    Returns:
        Encoded integer or None if the value cannot be parsed
    """
    if not value:
        return None
    candidate = value.strip()
    if not candidate:
        return None
    parts = re.split(r"[._-]", candidate)
    numeric_parts: list[int] = []
    for part in parts:
        if not part:
            continue
        match = re.match(r"(\d+)", part)
        if not match:
            return None
        numeric_parts.append(int(match.group(1)))
        if len(numeric_parts) >= 4:
            break
    if not numeric_parts:
        return None
    while len(numeric_parts) < 4:
        numeric_parts.append(0)

    encoded = 0
    for component in numeric_parts[:4]:
        encoded = encoded * 10000 + min(component, 9999)
    return encoded


def _tokens_from_cpes(cpes: list[str]) -> list[str]:
    tokens: set[str] = set()
    for cpe in cpes:
        if not isinstance(cpe, str):
            continue
        parsed = _parse_cpe_uri_details(cpe)
        if not parsed:
            continue
        vendor = parsed.get("vendor_raw") or parsed.get("vendor")
        product = parsed.get("product_raw") or parsed.get("product")
        version = parsed.get("version")
        tokens.update(
            _build_version_tokens(
                vendor,
                product,
                version,
                None,
                None,
                None,
                None,
            )
        )
    return sorted(tokens)


def _normalize_display_label(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.replace("_", " ").strip()
    return candidate or None


def _parse_cpe_uri_for_display(cpe: str) -> tuple[str | None, str | None, str | None]:
    if not isinstance(cpe, str) or not cpe:
        return None, None, None
    parts = cpe.split(":")
    if len(parts) < 6:
        return None, None, None

    vendor_raw = parts[3].replace("\\", "").strip()
    product_raw = parts[4].replace("\\", "").strip()
    version_raw = parts[5].replace("\\", "").strip()

    vendor = _normalize_display_label(vendor_raw)
    product = _normalize_display_label(product_raw)
    version = version_raw if version_raw not in {"*", "-"} else None

    return vendor, product, version


def _build_impacted_products_payload(
    *,
    cpe_configurations: list[dict[str, Any]],
    cpematch_entries: list[dict[str, Any]] | None,
    cpes: list[str],
) -> list[dict[str, Any]]:
    # Collect matches per configuration to determine context
    config_groups: list[list[dict[str, Any]]] = []

    def _collect_matches_from_nodes(nodes: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
        collected: list[dict[str, Any]] = []
        if not isinstance(nodes, list):
            return collected
        for node in nodes:
            if not isinstance(node, dict):
                continue
            node_matches = node.get("matches")
            if isinstance(node_matches, list):
                for item in node_matches:
                    if isinstance(item, dict):
                        collected.append(item)
            collected.extend(_collect_matches_from_nodes(node.get("nodes")))
        return collected

    def _has_and_with_app_and_os(nodes: list[dict[str, Any]] | None) -> bool:
        """Check if configuration has AND operator with both app and OS nodes"""
        if not isinstance(nodes, list) or len(nodes) < 2:
            return False

        # Check if any node has AND operator at the parent level
        has_app = False
        has_os = False

        for node in nodes:
            if not isinstance(node, dict):
                continue
            matches = node.get("matches", [])
            for match in matches:
                if isinstance(match, dict):
                    part = str(match.get("part") or "").lower()
                    if part in ("a", "h"):
                        has_app = True
                    elif part == "o":
                        has_os = True

        return has_app and has_os

    for configuration in cpe_configurations or []:
        if isinstance(configuration, dict):
            nodes = configuration.get("nodes")
            matches = _collect_matches_from_nodes(nodes)
            if matches:
                # Store configuration context
                config_groups.append({
                    "matches": matches,
                    "is_and_context": _has_and_with_app_and_os(nodes)
                })

    if (not config_groups) and isinstance(cpematch_entries, list):
        cpematch_configurations, _, _ = _collect_cpe_data_from_cpematch(cpematch_entries)
        for configuration in cpematch_configurations:
            if isinstance(configuration, dict):
                nodes = configuration.get("nodes")
                matches = _collect_matches_from_nodes(nodes)
                if matches:
                    config_groups.append({
                        "matches": matches,
                        "is_and_context": _has_and_with_app_and_os(nodes)
                    })

    aggregated: dict[tuple[str | None, str | None], dict[str, Any]] = {}
    shared_environments: set[str] = set()

    # Process each configuration group
    for group in config_groups:
        matches = group["matches"]
        is_and_context = group["is_and_context"]

        # If AND context, collect OS as environments
        group_environments: set[str] = set()
        if is_and_context:
            for match in matches:
                part_value = str(match.get("part") or "").lower()
                if part_value == "o":
                    vendor_label = _normalize_display_label(match.get("vendorRaw") or match.get("vendor"))
                    product_label = _normalize_display_label(match.get("productRaw") or match.get("product"))
                    env_label = product_label or vendor_label
                    if env_label:
                        group_environments.add(env_label)

        # Process all matches
        for match in matches:
            part_value = str(match.get("part") or "").lower()
            vendor_label = _normalize_display_label(match.get("vendorRaw") or match.get("vendor"))
            product_label = _normalize_display_label(match.get("productRaw") or match.get("product"))

            # Skip OS entries - they should only appear as environments, not as products
            if part_value == "o":
                continue

            # Only include applications and hardware
            if part_value not in {"a", "h"}:
                continue

            if not vendor_label or not product_label:
                continue

            vendor_slug = slugify(vendor_label)
            product_slug = slugify(product_label)

            key = (vendor_slug or vendor_label.lower(), product_slug or product_label.lower())
            entry = aggregated.setdefault(
                key,
                {
                    "vendor": {"name": vendor_label, "slug": vendor_slug or None},
                    "product": {"name": product_label, "slug": product_slug or None},
                    "versions": set(),
                    "vulnerable": None,
                    "environments": set(),
                },
            )

            version_range = _format_version_range(match)
            if version_range:
                entry["versions"].add(version_range)

            vulnerable_flag = match.get("vulnerable")
            if vulnerable_flag is False:
                entry["vulnerable"] = False
            elif entry["vulnerable"] is None and vulnerable_flag is not False:
                entry["vulnerable"] = True

            # Add group environments to this entry
            if group_environments:
                entry["environments"].update(group_environments)

            # Also check for target software/hardware
            for field in ("targetSw", "targetHw", "target_sw", "target_hw"):
                value = match.get(field)
                if isinstance(value, str) and value.strip():
                    env_label = _normalize_display_label(value) or value.strip()
                    entry["environments"].add(env_label)

    if not aggregated:
        return _fallback_impacted_products_from_cpes_payload(
            cpes=cpes,
            shared_environments=shared_environments,
        )

    results: list[dict[str, Any]] = []
    for entry in aggregated.values():
        results.append(
            {
                "vendor": entry["vendor"],
                "product": entry["product"],
                "versions": sorted(entry["versions"], key=str.lower),
                "vulnerable": entry["vulnerable"],
                "environments": sorted(entry["environments"], key=str.lower),
            }
        )

    return sorted(
        results,
        key=lambda item: (item["vendor"]["name"].lower(), item["product"]["name"].lower()),
    )


def _fallback_impacted_products_from_cpes_payload(
    *,
    cpes: list[str],
    shared_environments: set[str],
) -> list[dict[str, Any]]:
    aggregated: dict[tuple[str | None, str | None], dict[str, Any]] = {}
    for cpe in cpes:
        vendor_label, product_label, version_label = _parse_cpe_uri_for_display(cpe)
        if not vendor_label or not product_label:
            continue

        vendor_slug = slugify(vendor_label)
        product_slug = slugify(product_label)
        key = (vendor_slug or vendor_label.lower(), product_slug or product_label.lower())
        entry = aggregated.setdefault(
            key,
            {
                "vendor": {"name": vendor_label, "slug": vendor_slug or None},
                "product": {"name": product_label, "slug": product_slug or None},
                "versions": set(),
                "vulnerable": True,
                "environments": set(),
            },
        )
        if version_label:
            entry["versions"].add(version_label)

    shared_sorted = sorted(shared_environments)
    results: list[dict[str, Any]] = []
    for entry in aggregated.values():
        environments = (
            sorted(entry["environments"], key=str.lower)
            if entry["environments"]
            else shared_sorted
        )
        results.append(
            {
                "vendor": entry["vendor"],
                "product": entry["product"],
                "versions": sorted(entry["versions"], key=str.lower),
                "vulnerable": entry["vulnerable"],
                "environments": environments,
            }
        )

    return sorted(
        results,
        key=lambda item: (item["vendor"]["name"].lower(), item["product"]["name"].lower()),
    )


def _has_version_constraints(entry: Mapping[str, Any]) -> bool:
    if any(
        isinstance(entry.get(field), str) and entry[field].strip()
        for field in (
            "versionStartIncluding",
            "versionStartExcluding",
            "versionEndIncluding",
            "versionEndExcluding",
        )
    ):
        return True
    version = entry.get("version")
    if isinstance(version, str) and version.strip():
        return True
    return False


def _format_version_range(match: Mapping[str, Any]) -> str | None:
    start_inc = match.get("versionStartIncluding")
    start_exc = match.get("versionStartExcluding")
    end_inc = match.get("versionEndIncluding")
    end_exc = match.get("versionEndExcluding")
    exact = match.get("version")

    has_end = (isinstance(end_exc, str) and end_exc.strip()) or (
        isinstance(end_inc, str) and end_inc.strip()
    )

    parts: list[str] = []
    if isinstance(start_inc, str) and start_inc.strip():
        if has_end:
            parts.append(f">= {start_inc.strip()}")
        else:
            parts.append(start_inc.strip())
    elif isinstance(start_exc, str) and start_exc.strip():
        parts.append(f"> {start_exc.strip()}")

    if isinstance(end_exc, str) and end_exc.strip():
        parts.append(f"< {end_exc.strip()}")
    elif isinstance(end_inc, str) and end_inc.strip():
        parts.append(f"<= {end_inc.strip()}")

    if not parts and isinstance(exact, str) and exact.strip():
        parts.append(exact.strip())

    if not parts:
        return None

    return ", ".join(parts)


def _select_description(entries: Any, *, lang: str = "en") -> str | None:
    if isinstance(entries, list):
        for entry in entries:
            if isinstance(entry, dict):
                value = entry.get("value")
                entry_lang = str(entry.get("lang") or "").lower()
                if isinstance(value, str) and (not lang or entry_lang == lang.lower()):
                    return value
    return None


def _collect_cpe_data_from_nvd(record: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    # NVD record can have configurations at top level or nested in record["cve"]["configurations"]
    import structlog
    log = structlog.get_logger()

    configurations = record.get("configurations")
    if not isinstance(configurations, list):
        cve_wrapper = record.get("cve")
        if isinstance(cve_wrapper, dict):
            configurations = cve_wrapper.get("configurations")
            if configurations:
                log.debug("normalizer.found_nested_configs", count=len(configurations))
        else:
            log.debug("normalizer.no_cve_wrapper", record_keys=list(record.keys())[:5])
    if not isinstance(configurations, list):
        log.debug("normalizer.no_configurations", has_record=bool(record))
        return [], [], []

    normalized_configurations: list[dict[str, Any]] = []
    collected_criteria: list[str] = []
    collected_tokens: set[str] = set()

    def normalize_node(node: Any) -> tuple[dict[str, Any] | None, list[str], set[str]]:
        if not isinstance(node, dict):
            return None, [], set()

        operator = node.get("operator")
        negate = bool(node.get("negate", False))

        normalized: dict[str, Any] = {}
        if isinstance(operator, str) and operator.strip():
            normalized["operator"] = operator.strip().upper()
        elif "operator" in node:
            normalized["operator"] = "OR"
        if negate:
            normalized["negate"] = True

        matches_raw = node.get("cpeMatch")
        node_criteria: list[str] = []
        node_tokens: set[str] = set()
        normalized_matches: list[dict[str, Any]] = []
        if isinstance(matches_raw, list):
            for entry in matches_raw:
                match_obj, match_criteria, match_tokens = _normalize_cpe_match(entry)
                if match_obj:
                    normalized_matches.append(match_obj)
                    node_criteria.extend(match_criteria)
                    node_tokens.update(match_tokens)
        if normalized_matches:
            normalized["matches"] = normalized_matches

        children_raw = node.get("nodes")
        normalized_children: list[dict[str, Any]] = []
        if isinstance(children_raw, list):
            for child in children_raw:
                child_obj, child_criteria, child_tokens = normalize_node(child)
                if child_obj:
                    normalized_children.append(child_obj)
                    node_criteria.extend(child_criteria)
                    node_tokens.update(child_tokens)
        if normalized_children:
            normalized["nodes"] = normalized_children

        if not normalized_matches and not normalized_children:
            return None, node_criteria, node_tokens

        if "operator" not in normalized:
            normalized["operator"] = "OR"

        return normalized, node_criteria, node_tokens

    for configuration in configurations:
        if not isinstance(configuration, dict):
            continue
        nodes = configuration.get("nodes")
        if not isinstance(nodes, list):
            continue
        normalized_nodes: list[dict[str, Any]] = []
        config_criteria: list[str] = []
        config_tokens: set[str] = set()
        for node in nodes:
            normalized_node, node_criteria, node_tokens = normalize_node(node)
            if normalized_node:
                normalized_nodes.append(normalized_node)
                config_criteria.extend(node_criteria)
                config_tokens.update(node_tokens)
        if normalized_nodes:
            normalized_configurations.append({"nodes": normalized_nodes})
            collected_criteria.extend(config_criteria)
            collected_tokens.update(config_tokens)

    return normalized_configurations, _merge_unique_strings(collected_criteria), sorted(collected_tokens)


def _collect_cpe_data_from_cpematch(entries: list[dict[str, Any]] | None) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    if not isinstance(entries, list):
        return [], [], []

    normalized_matches: list[dict[str, Any]] = []
    collected_criteria: list[str] = []
    collected_tokens: set[str] = set()

    for wrapper in entries:
        match_entry: Any = None
        if isinstance(wrapper, dict):
            candidate = wrapper.get("matchString")
            match_entry = candidate if isinstance(candidate, dict) else wrapper
        if not isinstance(match_entry, dict):
            continue
        normalized_match, criteria_list, tokens = _normalize_cpe_match(match_entry)
        if not normalized_match:
            continue
        normalized_matches.append(normalized_match)
        collected_criteria.extend(criteria_list)
        collected_tokens.update(tokens)

    if not normalized_matches:
        return [], [], []

    configuration = {"nodes": [{"operator": "OR", "matches": normalized_matches}]}
    return [configuration], _merge_unique_strings(collected_criteria), sorted(collected_tokens)


def _normalize_cpe_match(entry: Any) -> tuple[dict[str, Any] | None, list[str], set[str]]:
    if not isinstance(entry, dict):
        return None, [], set()

    sanitized: dict[str, Any] = {}
    criteria = entry.get("criteria")
    criteria_value = criteria.strip() if isinstance(criteria, str) else None
    if not criteria_value:
        fallback = entry.get("cpeName") or entry.get("matchCriteriaId")
        if isinstance(fallback, str) and fallback.strip():
            criteria_value = fallback.strip()
    if criteria_value:
        sanitized["criteria"] = criteria_value

    match_id = entry.get("matchCriteriaId")
    if isinstance(match_id, str) and match_id.strip():
        sanitized["matchCriteriaId"] = match_id.strip()

    cpe_name = entry.get("cpeName")
    if isinstance(cpe_name, str) and cpe_name.strip():
        sanitized["cpeName"] = cpe_name.strip()

    sanitized["vulnerable"] = bool(entry.get("vulnerable", False))

    version_fields = {
        "version": entry.get("version"),
        "versionStartIncluding": entry.get("versionStartIncluding"),
        "versionStartExcluding": entry.get("versionStartExcluding"),
        "versionEndIncluding": entry.get("versionEndIncluding"),
        "versionEndExcluding": entry.get("versionEndExcluding"),
    }
    for field, value in version_fields.items():
        normalized = _normalize_version(value)
        if normalized:
            sanitized[field] = normalized

    parsed = _parse_cpe_uri_details(criteria_value or sanitized.get("cpeName"))
    vendor_key = None
    product_key = None
    if parsed:
        if parsed.get("part"):
            sanitized["part"] = parsed["part"]
        if parsed.get("vendor"):
            sanitized["vendor"] = parsed["vendor"]
        if parsed.get("vendor_raw"):
            sanitized["vendorRaw"] = parsed["vendor_raw"]
            vendor_key = parsed["vendor_raw"]
        elif parsed.get("vendor"):
            vendor_key = parsed["vendor"]
        if parsed.get("product"):
            sanitized["product"] = parsed["product"]
        if parsed.get("product_raw"):
            sanitized["productRaw"] = parsed["product_raw"]
            product_key = parsed["product_raw"]
        elif parsed.get("product"):
            product_key = parsed["product"]
        if parsed.get("target_sw"):
            sanitized["targetSw"] = parsed["target_sw"]
        if parsed.get("target_hw"):
            sanitized["targetHw"] = parsed["target_hw"]
        if "version" not in sanitized and parsed.get("version"):
            sanitized["version"] = parsed["version"]

    start_numeric = _encode_version_numeric(
        sanitized.get("versionStartIncluding")
        or sanitized.get("versionStartExcluding")
        or sanitized.get("version")
    )
    end_numeric = _encode_version_numeric(
        sanitized.get("versionEndIncluding")
        or sanitized.get("versionEndExcluding")
        or sanitized.get("version")
    )
    if start_numeric is not None:
        sanitized["versionStartNumeric"] = start_numeric
    if end_numeric is not None:
        sanitized["versionEndNumeric"] = end_numeric

    tokens = _build_version_tokens(
        vendor_key,
        product_key,
        sanitized.get("version"),
        sanitized.get("versionStartIncluding"),
        sanitized.get("versionStartExcluding"),
        sanitized.get("versionEndIncluding"),
        sanitized.get("versionEndExcluding"),
    )
    if tokens:
        sanitized["versionTokens"] = sorted(tokens)

    cleaned: dict[str, Any] = {"vulnerable": sanitized.pop("vulnerable", False)}
    for key, value in sanitized.items():
        if value is None:
            continue
        if isinstance(value, (list, dict)) and not value:
            continue
        cleaned[key] = value

    criteria_list = []
    if isinstance(cleaned.get("criteria"), str):
        criteria_list.append(cleaned["criteria"])
    elif isinstance(cleaned.get("cpeName"), str):
        criteria_list.append(cleaned["cpeName"])

    return cleaned, criteria_list, tokens


def _extract_cpes_from_nvd(record: dict[str, Any]) -> list[str]:
    _, criteria, _ = _collect_cpe_data_from_nvd(record)
    return criteria


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
    cpe_matches: list[dict[str, Any]] | None = None,
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
    # Title should be the CVE ID, summary is the description
    title = cve_id
    summary = description or cve_id

    references_raw = cve_wrapper.get("references") or []
    references: list[str] = []
    if isinstance(references_raw, list):
        for ref in references_raw:
            if isinstance(ref, dict):
                url = ref.get("url")
                if isinstance(url, str):
                    references.append(url)

    cwes = _extract_cwes_from_nvd(cve_wrapper)

    cpe_configurations, cpes, cpe_version_tokens = _collect_cpe_data_from_nvd(record)
    impacted_products = _build_impacted_products_payload(
        cpe_configurations=cpe_configurations,
        cpematch_entries=cpe_matches,
        cpes=cpes,
    )
    if cpe_matches:
        cpematch_configurations, cpematch_cpes, cpematch_tokens = _collect_cpe_data_from_cpematch(cpe_matches)
        if cpematch_configurations:
            cpe_configurations = _merge_configuration_sets(cpe_configurations, cpematch_configurations)
        if cpematch_cpes:
            cpes = _merge_unique_strings(cpes, cpematch_cpes)
        if cpematch_tokens:
            cpe_version_tokens = _merge_unique_strings(cpe_version_tokens, cpematch_tokens)

    vendors: set[str] = set()
    product_version_map: dict[str, set[str]] = {}
    for cpe_uri in cpes:
        part = _parse_cpe_uri_component(cpe_uri, 2)  # a, h, or o
        vendor = _parse_cpe_uri_component(cpe_uri, 3)
        product = _parse_cpe_uri_component(cpe_uri, 4)
        version = _parse_cpe_uri_component(cpe_uri, 5)
        vendor_label = _humanize_label(vendor)
        product_label = _humanize_label(product)
        version_value = _normalize_version(version)
        # Only add vendors/products from applications/hardware, not operating systems
        if part in ("a", "h"):
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

    if cpes:
        cpe_version_tokens = _merge_unique_strings(cpe_version_tokens, _tokens_from_cpes(cpes))

    raw_payload: dict[str, Any] = {"nvd": record}
    if cpe_matches:
        raw_payload["cpematch"] = cpe_matches

    # Store cpe_configurations as raw dicts - bypass Pydantic validation
    document = VulnerabilityDocument.model_construct(
        vuln_id=cve_id,
        source_id=cve_id,
        source="NVD",
        title=title,
        summary=summary,
        references=references,
        cwes=cwes,
        cpes=cpes,
        cpe_configurations=cpe_configurations,  # Pass dicts directly
        cpe_version_tokens=_merge_unique_strings(cpe_version_tokens),
        impacted_products=impacted_products,
        aliases=extract_ghsa_ids(references),
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
        raw=raw_payload,
    )
    return document, product_version_map


# ---------------------------------------------------------------------------
# GHSA (GitHub Security Advisories)
# ---------------------------------------------------------------------------

_SEVERITY_MAP: dict[str, str] = {
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


def _extract_ghsa_cvss(advisory: dict[str, Any]) -> tuple[CvssScore, dict[str, list[dict[str, Any]]]]:
    """Extract CVSS score and metrics from a GHSA advisory."""
    severities = advisory.get("cvss_severities") or {}
    severity_label = _SEVERITY_MAP.get((advisory.get("severity") or "").lower())

    cvss = CvssScore()
    cvss_metrics: dict[str, list[dict[str, Any]]] = {}

    # CVSS v3
    v3 = severities.get("cvss_v3") or {}
    v3_vector = v3.get("vector_string")
    v3_score = v3.get("score")
    if isinstance(v3_score, (int, float)) and v3_score > 0:
        cvss = CvssScore(
            version="3.1",
            base_score=float(v3_score),
            vector=v3_vector if isinstance(v3_vector, str) else None,
            severity=severity_label,
        )
        entry: dict[str, Any] = {"source": "GHSA", "type": "Primary"}
        data: dict[str, Any] = {"baseScore": float(v3_score), "version": "3.1"}
        if isinstance(v3_vector, str):
            data["vectorString"] = v3_vector
        if severity_label:
            data["baseSeverity"] = severity_label
        entry["data"] = data
        cvss_metrics["v31"] = [entry]

    # CVSS v4
    v4 = severities.get("cvss_v4") or {}
    v4_vector = v4.get("vector_string")
    v4_score = v4.get("score")
    if isinstance(v4_score, (int, float)) and v4_score > 0 and isinstance(v4_vector, str):
        entry_v4: dict[str, Any] = {"source": "GHSA", "type": "Primary"}
        data_v4: dict[str, Any] = {"baseScore": float(v4_score), "version": "4.0", "vectorString": v4_vector}
        if severity_label:
            data_v4["baseSeverity"] = severity_label
        entry_v4["data"] = data_v4
        cvss_metrics["v40"] = [entry_v4]
        # Prefer v4 as primary if no v3
        if cvss.base_score is None:
            cvss = CvssScore(
                version="4.0",
                base_score=float(v4_score),
                vector=v4_vector,
                severity=severity_label,
            )

    # If we only have severity but no scores
    if cvss.base_score is None and severity_label:
        cvss = CvssScore(severity=severity_label)

    return cvss, cvss_metrics


def _extract_ghsa_package_info(
    advisory: dict[str, Any],
) -> tuple[list[str], list[str], list[str], dict[str, set[str]], list[dict[str, Any]]]:
    """
    Extract vendor/product/version info and impactedProducts from GHSA vulnerabilities array.
    Uses ecosystem as vendor (e.g. npm, pip, maven).

    Returns: (vendors, products, product_versions, product_version_map, impacted_products)
    """
    vendors: set[str] = set()
    products: set[str] = set()
    versions: set[str] = set()
    product_version_map: dict[str, set[str]] = {}
    impacted_products: list[dict[str, Any]] = []

    vulns = advisory.get("vulnerabilities") or []
    if not isinstance(vulns, list):
        return [], [], [], {}, []

    for vuln in vulns:
        if not isinstance(vuln, dict):
            continue

        pkg = vuln.get("package") or {}
        ecosystem = pkg.get("ecosystem")
        package_name = pkg.get("name")

        if not isinstance(package_name, str) or not package_name.strip():
            continue

        package_name = package_name.strip()
        ecosystem_name = ecosystem.strip() if isinstance(ecosystem, str) and ecosystem.strip() else "Unknown"

        vendors.add(ecosystem_name)
        products.add(package_name)

        version_range = vuln.get("vulnerable_version_range")
        patched = vuln.get("first_patched_version")

        ver_strings: list[str] = []
        if isinstance(version_range, str) and version_range.strip():
            ver_strings.append(version_range.strip())
            # Use vulnerable_version_range for product_versions display
            bucket = product_version_map.setdefault(package_name, set())
            bucket.add(version_range.strip())
            versions.add(version_range.strip())

        vendor_slug = slugify(ecosystem_name) or ecosystem_name.lower()
        product_slug = slugify(package_name) or package_name.lower()

        impacted_products.append({
            "vendor": {"name": ecosystem_name, "slug": vendor_slug},
            "product": {"name": package_name, "slug": product_slug},
            "versions": ver_strings,
            "patchedVersions": [patched.strip()] if isinstance(patched, str) and patched.strip() else [],
            "vulnerable": True,
            "environments": [ecosystem_name],
        })

    return sorted(vendors), sorted(products), sorted(versions), product_version_map, impacted_products


def build_document_from_ghsa(
    advisory: dict[str, Any],
    *,
    ingested_at: datetime,
) -> tuple[VulnerabilityDocument, dict[str, set[str]]] | None:
    """
    Build a VulnerabilityDocument from a GitHub Security Advisory.
    Used for GHSA-only advisories (no CVE ID assigned).

    Returns (document, product_version_map) or None if advisory is invalid.
    """
    ghsa_id = advisory.get("ghsa_id")
    if not isinstance(ghsa_id, str) or not ghsa_id.strip():
        return None
    ghsa_id = ghsa_id.strip().upper()

    cve_id = advisory.get("cve_id")
    vuln_id = cve_id.strip().upper() if isinstance(cve_id, str) and cve_id.strip() else ghsa_id

    title = vuln_id
    summary = advisory.get("description") or advisory.get("summary") or vuln_id
    if isinstance(summary, str) and len(summary) > 10000:
        summary = summary[:10000]

    # References
    references: list[str] = []
    refs_raw = advisory.get("references") or []
    if isinstance(refs_raw, list):
        for ref in refs_raw:
            if isinstance(ref, str):
                references.append(ref)

    # CWEs
    cwes: list[str] = []
    cwes_raw = advisory.get("cwes") or []
    if isinstance(cwes_raw, list):
        for cwe in cwes_raw:
            if isinstance(cwe, dict):
                cwe_id = cwe.get("cwe_id")
                if isinstance(cwe_id, str) and cwe_id.strip():
                    cwes.append(cwe_id.strip())

    # Aliases
    aliases: list[str] = []
    identifiers = advisory.get("identifiers") or []
    seen_upper: set[str] = set()
    seen_upper.add(vuln_id.upper())
    if isinstance(identifiers, list):
        for ident in identifiers:
            if isinstance(ident, dict):
                val = ident.get("value")
                if isinstance(val, str) and val.strip():
                    normed = val.strip().upper() if val.strip().upper().startswith(("GHSA-", "MAL-", "PYSEC-")) else val.strip()
                    if normed.upper() not in seen_upper:
                        seen_upper.add(normed.upper())
                        aliases.append(normed)
    # CVSS
    cvss, cvss_metrics = _extract_ghsa_cvss(advisory)

    # Package info
    vendors, products, product_versions, product_version_map, impacted_products = _extract_ghsa_package_info(advisory)

    # Timestamps
    published = _parse_datetime(advisory.get("published_at"), allow_none=True)
    modified = _parse_datetime(advisory.get("updated_at"), fallback=published, allow_none=True)

    # Withdrawn check
    rejected = advisory.get("withdrawn_at") is not None

    document = VulnerabilityDocument.model_construct(
        vuln_id=vuln_id,
        source_id=ghsa_id,
        source="GHSA",
        title=title,
        summary=summary,
        references=references,
        cwes=cwes,
        cpes=[],
        cpe_configurations=[],
        cpe_version_tokens=[],
        impacted_products=impacted_products,
        aliases=aliases,
        rejected=rejected,
        assigner=None,
        exploited=None,
        epss_score=None,
        vendors=vendors,
        products=products,
        product_versions=product_versions,
        vendor_slugs=[slugify(v) or v.lower() for v in vendors],
        product_slugs=[slugify(p) or p.lower() for p in products],
        product_version_ids=[],
        cvss=cvss,
        cvss_metrics=cvss_metrics,
        published=published,
        modified=modified,
        ingested_at=ingested_at.astimezone(UTC),
        raw={"ghsa": advisory},
    )
    return document, product_version_map


# ---------------------------------------------------------------------------
# OSV.dev helpers
# ---------------------------------------------------------------------------

# Mapping from OSV ecosystem names to display names
_OSV_ECOSYSTEM_MAP: dict[str, str] = {
    "npm": "npm",
    "PyPI": "pip",
    "Go": "Go",
    "Maven": "Maven",
    "RubyGems": "RubyGems",
    "crates.io": "Cargo",
    "NuGet": "NuGet",
    "Packagist": "Packagist",
    "Pub": "Pub",
    "Hex": "Hex",
}


def extract_osv_downstream_references(
    osv_record: dict[str, Any],
    vuln_id: str,
) -> list[str]:
    """Generate reference URLs from downstream distro entries in the ``related`` field.

    Scans for Debian (DSA-/DLA-) and Ubuntu (USN-) related entries and
    produces security-tracker URLs.  Does NOT add the distro IDs as aliases.
    """
    related = osv_record.get("related") or []
    if not isinstance(related, list) or not vuln_id.upper().startswith("CVE-"):
        return []

    refs: list[str] = []
    has_debian = any(isinstance(r, str) and (r.startswith("DSA-") or r.startswith("DLA-")) for r in related)
    has_ubuntu = any(isinstance(r, str) and r.startswith("USN-") for r in related)

    if has_debian:
        refs.append(f"https://security-tracker.debian.org/tracker/{vuln_id}")
    if has_ubuntu:
        refs.append(f"https://ubuntu.com/security/{vuln_id}")

    return refs


def _extract_osv_package_info(
    osv_record: dict[str, Any],
) -> tuple[list[str], list[str], list[str], dict[str, set[str]], list[dict[str, Any]]]:
    """
    Extract vendor/product/version info and impactedProducts from an OSV record.

    Returns: (vendors, products, product_versions, product_version_map, impacted_products)
    """
    vendors: set[str] = set()
    products: set[str] = set()
    versions: set[str] = set()
    product_version_map: dict[str, set[str]] = {}
    impacted_products: list[dict[str, Any]] = []

    affected = osv_record.get("affected") or []
    if not isinstance(affected, list):
        return [], [], [], {}, []

    for entry in affected:
        if not isinstance(entry, dict):
            continue

        pkg = entry.get("package") or {}
        ecosystem = pkg.get("ecosystem")
        package_name = pkg.get("name")

        if not isinstance(package_name, str) or not package_name.strip():
            continue

        package_name = package_name.strip()
        ecosystem_name = _OSV_ECOSYSTEM_MAP.get(ecosystem, ecosystem) if isinstance(ecosystem, str) else "Unknown"

        vendors.add(ecosystem_name)
        products.add(package_name)

        # Collect version strings
        ver_strings: list[str] = []
        patched_versions: list[str] = []

        # Explicit versions list
        explicit_versions = entry.get("versions") or []
        if isinstance(explicit_versions, list):
            for v in explicit_versions:
                if isinstance(v, str) and v.strip():
                    versions.add(v.strip())
                    bucket = product_version_map.setdefault(package_name, set())
                    bucket.add(v.strip())

        # Version ranges (SEMVER / ECOSYSTEM / GIT)
        ranges = entry.get("ranges") or []
        if isinstance(ranges, list):
            for range_obj in ranges:
                if not isinstance(range_obj, dict):
                    continue
                events = range_obj.get("events") or []
                introduced = None
                fixed = None
                for event in events:
                    if not isinstance(event, dict):
                        continue
                    if "introduced" in event:
                        introduced = event["introduced"]
                    if "fixed" in event:
                        fixed = event["fixed"]

                if introduced is not None:
                    range_str = f">={introduced}"
                    if fixed is not None:
                        range_str += f" <{fixed}"
                        patched_versions.append(str(fixed))
                    ver_strings.append(range_str)

        # Fall back to explicit versions if no ranges produced version strings
        if not ver_strings and explicit_versions:
            ver_strings = [v.strip() for v in explicit_versions if isinstance(v, str) and v.strip()]

        vendor_slug = slugify(ecosystem_name) or ecosystem_name.lower()
        product_slug = slugify(package_name) or package_name.lower()

        impacted_products.append({
            "vendor": {"name": ecosystem_name, "slug": vendor_slug},
            "product": {"name": package_name, "slug": product_slug},
            "versions": ver_strings,
            "patchedVersions": patched_versions,
            "vulnerable": True,
            "environments": [ecosystem_name],
        })

    return sorted(vendors), sorted(products), sorted(versions), product_version_map, impacted_products


def _extract_osv_cvss(
    osv_record: dict[str, Any],
) -> tuple[CvssScore, dict[str, list[dict[str, Any]]]]:
    """Extract CVSS score and metrics from an OSV record."""
    cvss = CvssScore()
    cvss_metrics: dict[str, list[dict[str, Any]]] = {}

    severity_entries = osv_record.get("severity") or []
    if not isinstance(severity_entries, list):
        severity_entries = []

    for sev in severity_entries:
        if not isinstance(sev, dict):
            continue
        sev_type = sev.get("type")
        score_str = sev.get("score")
        if not isinstance(score_str, str):
            continue

        if sev_type == "CVSS_V3":
            parsed = _parse_cvss_vector_string(score_str)
            version = parsed.get("version", "3.1")
            severity_label = None
            # Try to infer severity from the vector components
            base_score_str = parsed.get("baseScore")
            base_score: float | None = None
            if isinstance(base_score_str, str):
                try:
                    base_score = float(base_score_str)
                except (ValueError, TypeError):
                    pass
            severity_label = _infer_severity_from_score(base_score, version) if base_score else None
            cvss = CvssScore(
                version=version,
                base_score=base_score,
                vector=score_str,
                severity=severity_label,
            )
            version_key = "v31" if version in ("3.0", "3.1") else f"v{version.replace('.', '')}"
            entry: dict[str, Any] = {"source": "OSV", "type": "Primary"}
            data: dict[str, Any] = {"vectorString": score_str, "version": version}
            if base_score is not None:
                data["baseScore"] = base_score
            if severity_label:
                data["baseSeverity"] = severity_label
            entry["data"] = data
            cvss_metrics[version_key] = [entry]

        elif sev_type == "CVSS_V4":
            entry_v4: dict[str, Any] = {"source": "OSV", "type": "Primary"}
            data_v4: dict[str, Any] = {"vectorString": score_str, "version": "4.0"}
            entry_v4["data"] = data_v4
            cvss_metrics["v40"] = [entry_v4]
            if cvss.base_score is None:
                cvss = CvssScore(
                    version="4.0",
                    base_score=None,
                    vector=score_str,
                    severity=None,
                )

    # Fall back to database_specific severity
    if cvss.base_score is None and cvss.severity is None:
        db_specific = osv_record.get("database_specific") or {}
        sev_str = db_specific.get("severity")
        if isinstance(sev_str, str) and sev_str.lower() in ("critical", "high", "medium", "low"):
            cvss = CvssScore(severity=sev_str.lower())

    return cvss, cvss_metrics


def build_document_from_osv(
    osv_record: dict[str, Any],
    *,
    ingested_at: datetime,
) -> tuple[VulnerabilityDocument, dict[str, set[str]]] | None:
    """
    Build a VulnerabilityDocument from an OSV.dev record.
    Used for standalone OSV entries (MAL-*, PYSEC-*, etc. without CVE alias).

    Returns (document, product_version_map) or None if record is invalid.
    """
    raw_osv_id = osv_record.get("id")
    if not isinstance(raw_osv_id, str) or not raw_osv_id.strip():
        return None
    raw_osv_id = raw_osv_id.strip()  # original case — preserved for source_id / URLs

    # Normalize GHSA/MAL/PYSEC prefixed IDs to uppercase (matches GHSA pipeline convention)
    _UPPER_PREFIXES = ("GHSA-", "MAL-", "PYSEC-")
    osv_id = raw_osv_id.upper() if raw_osv_id.upper().startswith(_UPPER_PREFIXES) else raw_osv_id

    # Determine vuln_id: use CVE alias if available, otherwise OSV ID
    aliases_raw = osv_record.get("aliases") or []
    if not isinstance(aliases_raw, list):
        aliases_raw = []

    cve_alias: str | None = None
    ghsa_alias: str | None = None
    for alias in aliases_raw:
        if not isinstance(alias, str) or not alias.strip():
            continue
        upper = alias.strip().upper()
        if upper.startswith("CVE-") and cve_alias is None:
            cve_alias = upper
        elif upper.startswith("GHSA-") and ghsa_alias is None:
            ghsa_alias = upper

    # Prefer CVE > GHSA > OSV ID as canonical document ID
    if cve_alias:
        vuln_id = cve_alias
    elif ghsa_alias:
        vuln_id = ghsa_alias
    else:
        vuln_id = osv_id

    title = vuln_id

    summary = osv_record.get("details") or osv_record.get("summary") or vuln_id
    if isinstance(summary, str) and len(summary) > 10000:
        summary = summary[:10000]

    # References
    references: list[str] = []
    refs_raw = osv_record.get("references") or []
    if isinstance(refs_raw, list):
        for ref in refs_raw:
            if isinstance(ref, dict):
                url = ref.get("url")
                if isinstance(url, str) and url.strip():
                    references.append(url.strip())
            elif isinstance(ref, str):
                references.append(ref)

    # Add downstream distro reference URLs (Debian, Ubuntu)
    for downstream_url in extract_osv_downstream_references(osv_record, vuln_id):
        if downstream_url not in references:
            references.append(downstream_url)

    # CWEs from database_specific
    cwes: list[str] = []
    db_specific = osv_record.get("database_specific") or {}
    cwe_ids = db_specific.get("cwe_ids") or []
    if isinstance(cwe_ids, list):
        for cwe_id in cwe_ids:
            if isinstance(cwe_id, str) and cwe_id.strip():
                cwes.append(cwe_id.strip())

    # Aliases (case-insensitive dedup)
    aliases: list[str] = []
    seen_upper: set[str] = {vuln_id.upper()}
    if osv_id.upper() != vuln_id.upper():
        aliases.append(osv_id)
        seen_upper.add(osv_id.upper())
    for alias in aliases_raw:
        if isinstance(alias, str) and alias.strip():
            normed = alias.strip().upper() if alias.strip().upper().startswith(("GHSA-", "MAL-", "PYSEC-", "CVE-")) else alias.strip()
            if normed.upper() not in seen_upper:
                seen_upper.add(normed.upper())
                aliases.append(normed)

    # CVSS
    cvss, cvss_metrics = _extract_osv_cvss(osv_record)

    # Package info
    vendors, products, product_versions, product_version_map, impacted_products = _extract_osv_package_info(osv_record)

    # Timestamps
    published = _parse_datetime(osv_record.get("published"), allow_none=True)
    modified = _parse_datetime(osv_record.get("modified"), fallback=published, allow_none=True)

    # Withdrawn check
    rejected = osv_record.get("withdrawn") is not None

    document = VulnerabilityDocument.model_construct(
        vuln_id=vuln_id,
        source_id=raw_osv_id,
        source="OSV",
        title=title,
        summary=summary,
        references=references,
        cwes=cwes,
        cpes=[],
        cpe_configurations=[],
        cpe_version_tokens=[],
        impacted_products=impacted_products,
        aliases=aliases,
        rejected=rejected,
        assigner=None,
        exploited=None,
        epss_score=None,
        vendors=vendors,
        products=products,
        product_versions=product_versions,
        vendor_slugs=[slugify(v) or v.lower() for v in vendors],
        product_slugs=[slugify(p) or p.lower() for p in products],
        product_version_ids=[],
        cvss=cvss,
        cvss_metrics=cvss_metrics,
        published=published,
        modified=modified,
        ingested_at=ingested_at.astimezone(UTC),
        raw={"osv": osv_record},
    )
    return document, product_version_map
