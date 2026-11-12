"""Which advisory vendors can name an SBOM component.

The SBOM side of "Affected in your scans" and the dashboard's scan coverage
match a component to a CVE by package name. A name alone is not enough: npm's
``console`` package and Citrix NetScaler *Console* share it, and the numeric
version check then happily puts ``console@0.15.11`` below NetScaler's
``< 14.1-74.34``.

A component from a language registry (purl type npm, pypi, maven, …) can only
be what an advisory names when the advisory's vendor is that registry (GHSA and
OSV write ``npm`` / ``PyPI`` / ``Maven`` as the vendor), the package's own
namespace (``@angular`` → ``angular``, ``org.apache.logging.log4j`` →
``apache``), or the package itself (NVD's ``lodash:lodash``). OS and binary
packages (``deb``, ``apk``, ``rpm``, ``generic``, …) and components without a
purl keep the plain name match: there NVD's vendors are the projects
themselves (``openssl``, ``nodejs``) and no registry name exists to compare.
"""

from __future__ import annotations

from collections.abc import Iterable
from urllib.parse import unquote

from app.utils.strings import slugify

# purl type -> vendor slugs that stand for the registry itself.
LANGUAGE_ECOSYSTEM_VENDORS: dict[str, frozenset[str]] = {
    "npm": frozenset({"npm", "npmjs"}),
    "pypi": frozenset({"pypi", "pip", "python"}),
    "maven": frozenset({"maven"}),
    "golang": frozenset({"go", "golang"}),
    "cargo": frozenset({"cargo", "crates-io"}),
    "nuget": frozenset({"nuget"}),
    "gem": frozenset({"rubygems", "gem"}),
    "composer": frozenset({"packagist", "composer"}),
    "pub": frozenset({"pub"}),
    "hex": frozenset({"hex"}),
    "swift": frozenset({"swift", "swiftpm"}),
    "cocoapods": frozenset({"cocoapods"}),
    "conda": frozenset({"conda"}),
    "github": frozenset({"github-actions"}),
    "githubactions": frozenset({"github-actions"}),
}

# Namespace pieces that say nothing about who makes a package.
_NOISE_SEGMENTS = frozenset({"com", "org", "net", "io", "dev", "co", "www", "github", "gitlab"})


def _purl_type_and_namespace(purl: str | None) -> tuple[str | None, str | None]:
    if not purl or not isinstance(purl, str) or not purl.startswith("pkg:"):
        return None, None
    body = purl[4:].split("?", 1)[0].split("#", 1)[0]
    body = body.rsplit("@", 1)[0] if "@" in body.split("/")[-1] else body
    parts = [p for p in body.split("/") if p]
    if not parts:
        return None, None
    purl_type = parts[0].lower()
    namespace = "/".join(parts[1:-1]) if len(parts) > 2 else None
    return purl_type, unquote(namespace) if namespace else None


def allowed_vendor_slugs(purl: str | None, name: str | None) -> frozenset[str] | None:
    """Vendor slugs an advisory may carry to name this component.

    ``None`` means any vendor: the component is no language-registry package
    (OS / binary / generic / no purl), so the name match stays as it was.
    """
    purl_type, namespace = _purl_type_and_namespace(purl)
    registry = LANGUAGE_ECOSYSTEM_VENDORS.get(purl_type or "")
    if registry is None:
        return None
    allowed: set[str] = set(registry)
    if name:
        allowed.add(slugify(name))
        # npm scoped names arrive as "@scope/pkg" in the SBOM name as well.
        if name.startswith("@") and "/" in name:
            allowed.add(slugify(name[1:].split("/", 1)[0]))
    if namespace:
        allowed.add(slugify(namespace.lstrip("@")))
        for segment in namespace.replace("/", ".").split("."):
            segment = segment.strip().lstrip("@")
            if segment and segment.lower() not in _NOISE_SEGMENTS:
                allowed.add(slugify(segment))
    return frozenset(s for s in allowed if s)


def vendor_names_component(allowed: frozenset[str] | None, vendor_values: Iterable[str | None]) -> bool:
    """Whether any of an advisory entry's vendor values fits the component.

    An entry without vendor information is not held against the component.
    """
    if allowed is None:
        return True
    slugs = {slugify(v) for v in vendor_values if isinstance(v, str) and v.strip()}
    if not slugs:
        return True
    return not slugs.isdisjoint(allowed)
