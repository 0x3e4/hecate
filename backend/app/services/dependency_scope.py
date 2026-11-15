"""Dependency scope of SBOM components and the findings in them.

Vocabulary (kept small on purpose): ``runtime`` (shipped / needed to run),
``optional`` (an optional dependency that may or may not be installed), ``dev``
(development, test and build tooling) and ``None`` for unknown. Only the
source that knows says something: a lockfile flag, a manifest section, a
CycloneDX ``scope`` or Trivy's ``Dev`` flag. Everything else stays unknown.

Merge rule when files or scanners disagree about the same (name, version):
runtime wins over optional, optional over dev (the conservative order: a
value that could hide a finding never beats one that keeps it visible), and
unknown never overrides a known value.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

SCOPES = ("runtime", "optional", "dev")
_RANK = {"runtime": 3, "optional": 2, "dev": 1}

_ALIASES = {
    "runtime": "runtime",
    "required": "runtime",
    "main": "runtime",
    "prod": "runtime",
    "production": "runtime",
    "compile": "runtime",
    "optional": "optional",
    "dev": "dev",
    "development": "dev",
    "test": "dev",
    "build": "dev",
    "excluded": "dev",  # CycloneDX: not part of the shipped artifact
}


def normalize_scope(value: Any) -> str | None:
    """Map a scope spelling to the vocabulary; anything unknown is ``None``."""
    if not isinstance(value, str):
        return None
    return _ALIASES.get(value.strip().lower())


def merge_scope(current: str | None, incoming: str | None) -> str | None:
    """Runtime > optional > dev; ``None`` never overrides a known value."""
    if incoming not in _RANK:
        return current if current in _RANK else None
    if current not in _RANK:
        return incoming
    return incoming if _RANK[incoming] > _RANK[current] else current


def cyclonedx_component_scope(component: dict[str, Any]) -> str | None:
    """Scope of a CycloneDX component: Hecate's own property, then ``scope``."""
    for prop in component.get("properties") or []:
        if isinstance(prop, dict) and prop.get("name") == "hecate:scope":
            found = normalize_scope(prop.get("value"))
            if found:
                return found
    return normalize_scope(component.get("scope"))


def package_key(name: str) -> str:
    """Spelling-insensitive package name (PyPI normalisation, case folded)."""
    return re.sub(r"[-_.]+", "-", (name or "").strip().lower())


def version_key(version: str) -> str:
    v = (version or "").strip()
    return v[1:] if v[:1] in ("v", "V") and v[1:2].isdigit() else v


def purl_type(purl: str | None) -> str:
    """The ecosystem of a purl (``pkg:npm/...`` -> ``npm``), or ``""``."""
    if isinstance(purl, str) and purl.startswith("pkg:") and "/" in purl:
        return purl[4:].split("/", 1)[0].strip().lower()
    return ""


class ScopeIndex:
    """Merged scopes of a scan's components, looked up for its findings.

    Keyed by ecosystem (purl type) as well as the package name: a polyglot
    repository can ship npm ``dummy-lib`` as a dev dependency next to a PyPI
    ``dummy_lib`` at runtime, and the npm scope must not mark the PyPI finding
    ``dev`` (a dev-scope VEX rule would then set it ``not_affected``).
    A component without a purl has the ecosystem ``""``.
    """

    def __init__(self, components: Iterable[tuple[Any, ...]]) -> None:
        self.by_component: dict[tuple[str, str], str] = {}
        self._by_key: dict[tuple[str, str, str], str] = {}
        self._by_name: dict[tuple[str, str], str] = {}
        self._ecosystems: dict[str, set[str]] = {}
        for entry in components:
            name, version, scope = entry[0], entry[1], entry[2]
            ecosystem = (entry[3] if len(entry) > 3 else "") or ""
            if not name:
                continue
            pkey, vkey = package_key(name), version_key(version)
            # Unscoped components count too: they are what tells a PyPI
            # dummy_lib apart from a scoped npm dummy-lib.
            self._ecosystems.setdefault(pkey, set()).add(ecosystem)
            if scope not in _RANK:
                continue
            raw = (name, version or "")
            merged = merge_scope(self.by_component.get(raw), scope)
            if merged:
                self.by_component[raw] = merged
            merged = merge_scope(self._by_key.get((ecosystem, pkey, vkey)), scope)
            if merged:
                self._by_key[(ecosystem, pkey, vkey)] = merged
            merged = merge_scope(self._by_name.get((ecosystem, pkey)), scope)
            if merged:
                self._by_name[(ecosystem, pkey)] = merged

    def __bool__(self) -> bool:
        return bool(self.by_component)

    def for_package(self, name: str, version: str, ecosystem: str | None = None) -> str | None:
        """Scope of a finding's package: exact (name, version), else the name.

        Only components of the finding's own ecosystem count, plus purl-less
        ones. The name fallback covers version spellings that differ between
        scanners; it merges every version of that name, so a runtime copy
        anywhere keeps the finding runtime. It never crosses into another
        known ecosystem; a finding of unknown ecosystem gets the name fallback
        only while a single ecosystem knows the name.
        """
        pkey, vkey = package_key(name), version_key(version)
        known = self._ecosystems.get(pkey)
        if not known:
            return None
        if not ecosystem:
            found: str | None = None
            for eco in known:
                found = merge_scope(found, self._by_key.get((eco, pkey, vkey)))
            if found is None and len(known) == 1:
                found = self._by_name.get((next(iter(known)), pkey))
            return found
        exact = merge_scope(self._by_key.get((ecosystem, pkey, vkey)), self._by_key.get(("", pkey, vkey)))
        if exact:
            return exact
        found = self._by_name.get((ecosystem, pkey))
        # A purl-less component may stand in for this ecosystem only while no
        # other ecosystem knows the name.
        if known <= {ecosystem, ""}:
            found = merge_scope(found, self._by_name.get(("", pkey)))
        return found
