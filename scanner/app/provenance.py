"""Provenance verification for SBOM components.

Checks package registry APIs for attestations, signatures, and provenance data
to verify supply chain integrity. Supports npm, PyPI, Go, Maven, RubyGems,
Cargo, NuGet, and Docker.

References:
- npm: Sigstore-based provenance (GitHub Actions build attestations)
- PyPI: PEP 740 attestations (Trusted Publishers, Sigstore)
- Go: Checksum database (sum.golang.org, transparency log)
- Maven: PGP signatures, Sigstore attestations
- RubyGems: Sigstore attestations (since 2024)
- Cargo: crates.io checksum verification
- NuGet: Package signature validation
- Docker: Docker Content Trust, cosign signatures, SLSA provenance
"""

from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import quote

import httpx

log = logging.getLogger(__name__)

_TIMEOUT = 5.0  # seconds per request
_CONCURRENCY = 10  # max concurrent registry requests
_CA_BUNDLE = os.environ.get("HTTP_CA_BUNDLE") or None


@dataclass
class ProvenanceResult:
    """Result of a provenance verification check."""

    verified: bool | None = None  # True=has provenance, False=no provenance, None=unknown/error
    source_repo: str | None = None
    build_system: str | None = None
    attestation_type: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dict. Always includes 'verified' key so the result is never empty."""
        d = {k: v for k, v in asdict(self).items() if v is not None}
        # Always include verified so downstream code can detect this was checked
        if "verified" not in d:
            d["verified"] = None
        return d


# ---------------------------------------------------------------------------
# Per-ecosystem checkers
# ---------------------------------------------------------------------------


async def _check_npm(client: httpx.AsyncClient, name: str, version: str) -> ProvenanceResult:
    """Check npm registry for Sigstore provenance attestations."""
    url = f"https://registry.npmjs.org/{quote(name, safe='@/')}/{version}"
    resp = await client.get(url)
    if resp.status_code != 200:
        return ProvenanceResult()

    data = resp.json()
    dist = data.get("dist", {})

    # Check for attestations (newer Sigstore-based provenance)
    attestations = dist.get("attestations")
    if attestations:
        provenance = attestations.get("provenance", {})
        return ProvenanceResult(
            verified=True,
            source_repo=provenance.get("sourceRepository"),
            build_system="GitHub Actions" if "github" in str(provenance).lower() else None,
            attestation_type="sigstore",
        )

    # Check for npm signatures (older method)
    signatures = dist.get("signatures")
    if signatures:
        return ProvenanceResult(
            verified=True,
            attestation_type="npm-signature",
        )

    # Check for integrity hash (basic, always present)
    if dist.get("integrity"):
        return ProvenanceResult(verified=False, attestation_type=None)

    return ProvenanceResult(verified=False)


async def _check_pypi(client: httpx.AsyncClient, name: str, version: str) -> ProvenanceResult:
    """Check PyPI for PEP 740 attestations (Trusted Publishers)."""
    # First check package metadata
    url = f"https://pypi.org/pypi/{quote(name)}/{version}/json"
    resp = await client.get(url)
    if resp.status_code != 200:
        return ProvenanceResult()

    data = resp.json()

    # Check for attestations via PEP 740 endpoint
    try:
        att_url = f"https://pypi.org/integrity/{quote(name)}/{version}/"
        att_resp = await client.get(att_url)
        if att_resp.status_code == 200:
            att_data = att_resp.json()
            if att_data.get("attestations"):
                # Extract source repo from attestation if available
                source_repo = None
                for att in att_data.get("attestations", []):
                    env = att.get("verification_material", {}).get("certificate", {})
                    if "github.com" in str(env):
                        source_repo = str(env)
                        break
                return ProvenanceResult(
                    verified=True,
                    source_repo=source_repo,
                    build_system="Trusted Publisher",
                    attestation_type="pep740",
                )
    except Exception:
        pass

    # Check project URLs for source repo
    info = data.get("info", {})
    project_urls = info.get("project_urls") or {}
    source_repo = (
        project_urls.get("Source")
        or project_urls.get("Repository")
        or project_urls.get("Homepage")
    )

    return ProvenanceResult(verified=False, source_repo=source_repo)


async def _check_go(client: httpx.AsyncClient, name: str, version: str) -> ProvenanceResult:
    """Check Go checksum database for module verification."""
    # Normalize: go modules use v-prefixed versions
    v = version if version.startswith("v") else f"v{version}"
    url = f"https://sum.golang.org/lookup/{quote(name, safe='/')}@{v}"
    resp = await client.get(url)
    if resp.status_code == 200:
        return ProvenanceResult(
            verified=True,
            attestation_type="go-checksum-db",
            build_system="sum.golang.org",
        )
    return ProvenanceResult(verified=False)


async def _check_maven(client: httpx.AsyncClient, name: str, version: str) -> ProvenanceResult:
    """Check Maven Central for package signatures."""
    # Maven names are typically group:artifact
    parts = name.split(":")
    if len(parts) == 2:
        group, artifact = parts
    else:
        # Try splitting on . for group ID
        segments = name.rsplit(".", 1)
        if len(segments) == 2:
            group, artifact = segments
        else:
            return ProvenanceResult()

    url = f"https://search.maven.org/solrsearch/select?q=g:{quote(group)}+AND+a:{quote(artifact)}+AND+v:{quote(version)}&rows=1&wt=json"
    resp = await client.get(url)
    if resp.status_code != 200:
        return ProvenanceResult()

    data = resp.json()
    docs = data.get("response", {}).get("docs", [])
    if docs:
        # Maven Central requires PGP signatures for all uploads
        return ProvenanceResult(
            verified=True,
            attestation_type="pgp-signature",
            build_system="Maven Central",
        )
    return ProvenanceResult(verified=False)


async def _check_rubygems(client: httpx.AsyncClient, name: str, version: str) -> ProvenanceResult:
    """Check RubyGems for attestations."""
    url = f"https://rubygems.org/api/v2/rubygems/{quote(name)}/versions/{version}.json"
    resp = await client.get(url)
    if resp.status_code != 200:
        return ProvenanceResult()

    data = resp.json()
    # RubyGems added Sigstore attestations in 2024
    if data.get("attestations") or data.get("sha"):
        return ProvenanceResult(
            verified=bool(data.get("attestations")),
            attestation_type="sigstore" if data.get("attestations") else None,
            source_repo=data.get("source_code_uri"),
        )
    return ProvenanceResult(verified=False, source_repo=data.get("source_code_uri"))


async def _check_cargo(client: httpx.AsyncClient, name: str, version: str) -> ProvenanceResult:
    """Check crates.io for crate verification."""
    url = f"https://crates.io/api/v1/crates/{quote(name)}/{version}"
    headers = {"User-Agent": "hecate-scanner/1.0"}
    resp = await client.get(url, headers=headers)
    if resp.status_code != 200:
        return ProvenanceResult()

    data = resp.json()
    v = data.get("version", {})
    if v.get("checksum"):
        return ProvenanceResult(
            verified=True,
            attestation_type="crates-io-checksum",
            source_repo=data.get("crate", {}).get("repository"),
        )
    return ProvenanceResult(verified=False)


async def _check_nuget(client: httpx.AsyncClient, name: str, version: str) -> ProvenanceResult:
    """Check NuGet for package signatures."""
    url = f"https://api.nuget.org/v3/registration5-gz-semver2/{quote(name.lower())}/{version.lower()}.json"
    resp = await client.get(url)
    if resp.status_code != 200:
        return ProvenanceResult()

    data = resp.json()
    catalog = data.get("catalogEntry", {})
    # NuGet supports author and repository signatures
    if catalog.get("packageContent"):
        return ProvenanceResult(
            verified=True,
            attestation_type="nuget-signature",
            source_repo=catalog.get("projectUrl"),
        )
    return ProvenanceResult(verified=False)


async def _check_docker(client: httpx.AsyncClient, name: str, version: str) -> ProvenanceResult:
    """Check Docker registry for cosign signatures / SLSA provenance."""
    # For Docker Hub images, check for cosign attestations
    # This is a simplified check — full verification requires cosign binary
    registry = "registry-1.docker.io"
    repo = name if "/" in name else f"library/{name}"
    tag = version or "latest"

    # Get auth token for Docker Hub
    try:
        token_resp = await client.get(
            f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repo}:pull"
        )
        if token_resp.status_code != 200:
            return ProvenanceResult()
        token = token_resp.json().get("token", "")

        # Check for cosign signature tag (convention: sha256-<digest>.sig)
        headers = {"Authorization": f"Bearer {token}"}
        manifest_resp = await client.get(
            f"https://{registry}/v2/{repo}/manifests/{tag}",
            headers={**headers, "Accept": "application/vnd.docker.distribution.manifest.v2+json"},
        )
        if manifest_resp.status_code == 200:
            digest = manifest_resp.headers.get("docker-content-digest", "")
            if digest:
                # Check for cosign signature
                sig_tag = digest.replace("sha256:", "sha256-") + ".sig"
                sig_resp = await client.head(
                    f"https://{registry}/v2/{repo}/manifests/{sig_tag}",
                    headers=headers,
                )
                if sig_resp.status_code == 200:
                    return ProvenanceResult(
                        verified=True,
                        attestation_type="cosign",
                    )
            return ProvenanceResult(verified=False)
    except Exception:
        pass

    return ProvenanceResult()


# ---------------------------------------------------------------------------
# Ecosystem dispatcher
# ---------------------------------------------------------------------------

_ECOSYSTEM_MAP: dict[str, str] = {
    # purl types → ecosystem key
    "npm": "npm",
    "pypi": "pypi",
    "golang": "go",
    "maven": "maven",
    "gem": "rubygems",
    "cargo": "cargo",
    "nuget": "nuget",
    "docker": "docker",
    "oci": "docker",
    # Common SBOM type names
    "container": "docker",
    "library": "npm",  # fallback for generic libraries
}

_CHECKERS = {
    "npm": _check_npm,
    "pypi": _check_pypi,
    "go": _check_go,
    "maven": _check_maven,
    "rubygems": _check_rubygems,
    "cargo": _check_cargo,
    "nuget": _check_nuget,
    "docker": _check_docker,
}


def _normalize_version(version: str) -> str:
    """Strip semver range characters (^, ~, >=, etc.) to get a plain version."""
    if not version:
        return version
    # Remove leading semver range operators
    stripped = version.lstrip("^~>=<! ")
    # Handle compound ranges like ">=1.0.0 <2.0.0" — take the first version
    if " " in stripped:
        stripped = stripped.split()[0]
    # Remove trailing wildcards like ".x" or ".*"
    for suffix in (".x", ".*"):
        if stripped.endswith(suffix):
            stripped = stripped[: -len(suffix)]
    return stripped


def _detect_ecosystem(component: dict[str, Any]) -> str | None:
    """Detect ecosystem from a CycloneDX component dict."""
    # Try purl first
    purl = component.get("purl", "")
    if purl.startswith("pkg:"):
        purl_type = purl.split(":", 1)[1].split("/", 1)[0]
        return _ECOSYSTEM_MAP.get(purl_type)

    # Try component type
    comp_type = component.get("type", "")
    if comp_type in _ECOSYSTEM_MAP:
        return _ECOSYSTEM_MAP[comp_type]

    return None


async def check_provenance_batch(
    components: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Check provenance for a batch of SBOM components.

    Returns the components list with a `provenance` field added to each.
    """
    semaphore = asyncio.Semaphore(_CONCURRENCY)
    cache: dict[str, ProvenanceResult] = {}

    async def _check_one(
        client: httpx.AsyncClient, comp: dict[str, Any]
    ) -> None:
        name = comp.get("name", "")
        version = _normalize_version(comp.get("version", ""))
        ecosystem = _detect_ecosystem(comp)

        if not ecosystem or not name:
            comp["provenance"] = ProvenanceResult().to_dict()
            return

        if not version:
            comp["provenance"] = ProvenanceResult().to_dict()
            return

        cache_key = f"{ecosystem}:{name}:{version}"
        if cache_key in cache:
            comp["provenance"] = cache[cache_key].to_dict()
            return

        checker = _CHECKERS.get(ecosystem)
        if not checker:
            comp["provenance"] = ProvenanceResult().to_dict()
            return

        async with semaphore:
            try:
                result = await checker(client, name, version)
            except Exception as exc:
                log.debug("provenance_check_failed", name=name, version=version, error=str(exc))
                result = ProvenanceResult()

        cache[cache_key] = result
        comp["provenance"] = result.to_dict()

    async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True, verify=_CA_BUNDLE or True) as client:
        await asyncio.gather(
            *[_check_one(client, comp) for comp in components],
            return_exceptions=True,
        )

    return components
