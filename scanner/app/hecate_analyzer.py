"""Hecate Analyzer — extracts SBOM components from package manifests across all major ecosystems."""

from __future__ import annotations

import json
import re
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

import yaml

_SKIP_DIRS = frozenset({
    "node_modules", ".git", "vendor", "dist", "build",
    "__pycache__", ".tox", ".venv", "venv", ".next",
    "coverage", ".nyc_output", "bower_components",
    "target", "bin", "obj", ".gradle",
})


def _should_skip(path: Path) -> bool:
    return any(part in _SKIP_DIRS for part in path.parts)


def _lib_component(name: str, version: str, purl: str, source_file: str) -> dict[str, Any]:
    """Build a CycloneDX library component dict."""
    return {
        "type": "library",
        "name": name,
        "version": version,
        "purl": purl,
        "properties": [{"name": "hecate:source-file", "value": source_file}],
    }


def _extract_version(spec: str) -> str:
    """Extract a clean version from a version specifier (e.g., '^1.2.3' -> '1.2.3', '>=2.0,<3' -> '2.0')."""
    spec = spec.strip()
    # Try to extract first semver-like version
    m = re.search(r"(\d+(?:\.\d+)*(?:[a-zA-Z][\w.]*)?)", spec)
    return m.group(1) if m else spec

# ---------------------------------------------------------------------------
# Dockerfile parsing
# ---------------------------------------------------------------------------

_ARG_RE = re.compile(
    r"^\s*ARG\s+(\w+)(?:\s*=\s*(.+?))?\s*$",
    re.IGNORECASE | re.MULTILINE,
)

_FROM_RE = re.compile(
    r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+?)(?:\s+AS\s+(\S+))?\s*$",
    re.IGNORECASE | re.MULTILINE,
)

_COPY_FROM_RE = re.compile(
    r"^\s*COPY\s+--from=(\S+)",
    re.IGNORECASE | re.MULTILINE,
)

_VAR_RE = re.compile(r"\$\{(\w+)(?::?[-+]([^}]*))?\}|\$(\w+)")

_DOCKERFILE_GLOBS = ("Dockerfile", "Dockerfile.*", "*.dockerfile")


def _resolve_vars(value: str, args: dict[str, str]) -> str:
    """Resolve $VAR and ${VAR} / ${VAR:-default} / ${VAR-default} placeholders."""
    def _replace(m: re.Match) -> str:
        name = m.group(1) or m.group(3)
        fallback = m.group(2)
        resolved = args.get(name, "")
        if resolved:
            return resolved
        if fallback is not None:
            return fallback
        return m.group(0)  # unresolved — keep original
    return _VAR_RE.sub(_replace, value)


def _split_image_ref(ref: str) -> tuple[str, str]:
    """Split an image reference into (name, tag).  Handles registry/namespace/name:tag and @sha256 digests."""
    if ref.startswith("scratch"):
        return "scratch", ""
    # Digest reference: name@sha256:...
    if "@" in ref:
        name, digest = ref.split("@", 1)
        return name, digest
    # Tag reference: name:tag  (but beware registry port like registry:5000/img)
    parts = ref.split("/")
    last = parts[-1]
    if ":" in last:
        tag_sep = last.rsplit(":", 1)
        parts[-1] = tag_sep[0]
        return "/".join(parts), tag_sep[1]
    return ref, "latest"


def _image_to_component(name: str, version: str, source_file: str) -> dict[str, Any]:
    """Build a CycloneDX component dict for a container image reference."""
    # Build purl: pkg:docker/namespace/name@version
    purl_name = name.replace("/", "%2F") if "/" in name else name
    purl = f"pkg:docker/{purl_name}@{version}" if version else f"pkg:docker/{purl_name}"

    return {
        "type": "container",
        "name": name,
        "version": version,
        "purl": purl,
        "properties": [
            {"name": "hecate:source-file", "value": source_file},
        ],
    }


def parse_dockerfiles(source_dir: str) -> list[dict[str, Any]]:
    """Extract image references from all Dockerfiles in *source_dir*."""
    root = Path(source_dir)
    components: list[dict[str, Any]] = []

    dockerfile_paths: list[Path] = []
    for pattern in _DOCKERFILE_GLOBS:
        dockerfile_paths.extend(root.rglob(pattern))

    for df_path in dockerfile_paths:
        try:
            content = df_path.read_text(errors="replace")
        except OSError:
            continue

        rel_path = str(df_path.relative_to(root))

        # Collect ARG defaults for variable resolution
        args: dict[str, str] = {}
        for match in _ARG_RE.finditer(content):
            arg_name = match.group(1)
            arg_default = (match.group(2) or "").strip().strip('"').strip("'")
            if arg_default:
                args[arg_name] = arg_default

        # Track stage aliases so we can skip internal COPY --from= refs
        stage_aliases: set[str] = set()

        for match in _FROM_RE.finditer(content):
            image_ref = _resolve_vars(match.group(1), args)
            alias = match.group(2)
            if alias:
                stage_aliases.add(alias.lower())

            # Skip unresolved variables and scratch
            if image_ref.lower() == "scratch" or "${" in image_ref:
                continue

            name, version = _split_image_ref(image_ref)
            components.append(_image_to_component(name, version, rel_path))

        # COPY --from=<external_image> (not a build stage)
        for match in _COPY_FROM_RE.finditer(content):
            ref = _resolve_vars(match.group(1), args)
            # Skip numeric stage references (e.g. COPY --from=0)
            if ref.isdigit():
                continue
            if ref.lower() in stage_aliases:
                continue
            if "${" in ref:
                continue
            name, version = _split_image_ref(ref)
            components.append(_image_to_component(name, version, rel_path))

    return components


# ---------------------------------------------------------------------------
# docker-compose parsing
# ---------------------------------------------------------------------------

_COMPOSE_GLOBS = (
    "docker-compose*.yml",
    "docker-compose*.yaml",
    "compose.yml",
    "compose.yaml",
)


def parse_compose_files(source_dir: str) -> list[dict[str, Any]]:
    """Extract image references from docker-compose / compose files."""
    root = Path(source_dir)
    components: list[dict[str, Any]] = []

    compose_paths: list[Path] = []
    for pattern in _COMPOSE_GLOBS:
        compose_paths.extend(root.rglob(pattern))

    for cp in compose_paths:
        try:
            content = cp.read_text(errors="replace")
            data = yaml.safe_load(content)
        except (OSError, yaml.YAMLError):
            continue

        if not isinstance(data, dict):
            continue

        rel_path = str(cp.relative_to(root))
        services = data.get("services", {})
        if not isinstance(services, dict):
            continue

        for _svc_name, svc_def in services.items():
            if not isinstance(svc_def, dict):
                continue
            image = svc_def.get("image")
            if not isinstance(image, str) or not image.strip():
                continue
            resolved = _resolve_vars(image.strip(), {})
            if "${" in resolved:
                continue
            name, version = _split_image_ref(resolved)
            components.append(_image_to_component(name, version, rel_path))

    return components


# ---------------------------------------------------------------------------
# package.json fallback (only when no lockfile exists)
# ---------------------------------------------------------------------------

_LOCKFILES = frozenset({
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
    "bun.lockb",
})


def parse_package_jsons(source_dir: str) -> list[dict[str, Any]]:
    """Extract dependencies from package.json files that have no lockfile."""
    root = Path(source_dir)
    components: list[dict[str, Any]] = []

    for pj_path in root.rglob("package.json"):
        # Skip node_modules
        if "node_modules" in pj_path.parts:
            continue

        # Check if any lockfile exists in the same directory
        parent = pj_path.parent
        has_lockfile = any((parent / lf).exists() for lf in _LOCKFILES)
        if has_lockfile:
            continue

        try:
            data = json.loads(pj_path.read_text(errors="replace"))
        except (OSError, json.JSONDecodeError):
            continue

        if not isinstance(data, dict):
            continue

        rel_path = str(pj_path.relative_to(root))

        for dep_group in ("dependencies", "devDependencies"):
            deps = data.get(dep_group)
            if not isinstance(deps, dict):
                continue
            for dep_name, dep_version in deps.items():
                if not isinstance(dep_name, str) or not isinstance(dep_version, str):
                    continue
                purl = f"pkg:npm/{dep_name}@{dep_version}"
                components.append({
                    "type": "library",
                    "name": dep_name,
                    "version": dep_version,
                    "purl": purl,
                    "properties": [
                        {"name": "hecate:source-file", "value": rel_path},
                    ],
                })

    return components


# ---------------------------------------------------------------------------
# package-lock.json (npm v7+ and legacy v1)
# ---------------------------------------------------------------------------


def _npm_name_from_lockfile_path(path_key: str) -> str:
    """Convert a package-lock.json v7+ `packages` key to an npm package name.

    Keys look like "node_modules/@scope/name" or "node_modules/name" or
    "node_modules/foo/node_modules/bar" (nested). The effective name is the
    segment after the LAST `node_modules/`.
    """
    marker = "node_modules/"
    idx = path_key.rfind(marker)
    if idx < 0:
        return ""
    return path_key[idx + len(marker):]


def parse_package_lock_json(source_dir: str) -> list[dict[str, Any]]:
    """Extract resolved dependencies from package-lock.json (npm v1/v2/v3)."""
    root = Path(source_dir)
    components: list[dict[str, Any]] = []

    for pl_path in root.rglob("package-lock.json"):
        if _should_skip(pl_path):
            continue
        try:
            data = json.loads(pl_path.read_text(errors="replace"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue

        rel_path = str(pl_path.relative_to(root))
        seen: set[tuple[str, str]] = set()

        # Modern format (lockfileVersion >= 2): top-level `packages` dict.
        packages = data.get("packages")
        if isinstance(packages, dict):
            for key, entry in packages.items():
                if not isinstance(entry, dict) or not key:
                    continue
                # Skip the root project entry (key == "")
                name = entry.get("name") if isinstance(entry.get("name"), str) else _npm_name_from_lockfile_path(key)
                version = entry.get("version")
                if not name or not isinstance(version, str) or not version:
                    continue
                if (name, version) in seen:
                    continue
                seen.add((name, version))
                components.append({
                    "type": "library",
                    "name": name,
                    "version": version,
                    "purl": f"pkg:npm/{name}@{version}",
                    "properties": [{"name": "hecate:source-file", "value": rel_path}],
                })

        # Legacy format (lockfileVersion 1): recursive `dependencies` tree.
        def _walk_legacy(deps: dict[str, Any]) -> None:
            for name, entry in deps.items():
                if not isinstance(name, str) or not isinstance(entry, dict):
                    continue
                version = entry.get("version")
                if isinstance(version, str) and version and (name, version) not in seen:
                    seen.add((name, version))
                    components.append({
                        "type": "library",
                        "name": name,
                        "version": version,
                        "purl": f"pkg:npm/{name}@{version}",
                        "properties": [{"name": "hecate:source-file", "value": rel_path}],
                    })
                nested = entry.get("dependencies")
                if isinstance(nested, dict):
                    _walk_legacy(nested)

        legacy = data.get("dependencies")
        if isinstance(legacy, dict):
            _walk_legacy(legacy)

    return components


# ---------------------------------------------------------------------------
# yarn.lock (classic v1 text format + Berry YAML)
# ---------------------------------------------------------------------------


_YARN_HEADER_RE = re.compile(r'^(?P<spec>\S.*?)\s*:\s*$')
_YARN_VERSION_RE = re.compile(r'^\s+version\s+"?([^"\s]+)"?\s*$')
_YARN_RESOLVED_RE = re.compile(r'^\s+resolved\s+"?[^"]*"?\s*$')


def _yarn_name_from_spec(spec: str) -> str:
    """Pull the package name out of a yarn v1 lock spec header.

    Spec examples:
      "lodash@^4.17.21":
      "@babel/core@^7.12.3, @babel/core@^7.13.0":
      foo@1.0.0:
    """
    spec = spec.strip().strip('"')
    # Take the first comma-separated entry
    first = spec.split(",")[0].strip().strip('"')
    # Scoped package: @scope/name@range
    if first.startswith("@"):
        at = first.find("@", 1)
        return first[:at] if at > 0 else first
    at = first.find("@")
    return first[:at] if at > 0 else first


def parse_yarn_lock(source_dir: str) -> list[dict[str, Any]]:
    """Extract resolved dependencies from yarn.lock (v1 text + Berry YAML)."""
    root = Path(source_dir)
    components: list[dict[str, Any]] = []

    for yl_path in root.rglob("yarn.lock"):
        if _should_skip(yl_path):
            continue
        try:
            content = yl_path.read_text(errors="replace")
        except OSError:
            continue

        rel_path = str(yl_path.relative_to(root))
        seen: set[tuple[str, str]] = set()

        # Try Yarn Berry (YAML) first — starts with "__metadata:" map.
        if "__metadata:" in content[:200]:
            try:
                data = yaml.safe_load(content)
                if isinstance(data, dict):
                    for spec, entry in data.items():
                        if spec == "__metadata" or not isinstance(entry, dict):
                            continue
                        name = _yarn_name_from_spec(str(spec))
                        version = entry.get("version")
                        if name and isinstance(version, str) and version and (name, version) not in seen:
                            seen.add((name, version))
                            components.append({
                                "type": "library",
                                "name": name,
                                "version": version,
                                "purl": f"pkg:npm/{name}@{version}",
                                "properties": [{"name": "hecate:source-file", "value": rel_path}],
                            })
                    continue
            except yaml.YAMLError:
                pass  # fall through to classic parser

        # Classic v1 parser — block header followed by indented `version "x.y.z"`.
        current_spec: str | None = None
        for raw in content.splitlines():
            if not raw.strip() or raw.lstrip().startswith("#"):
                continue
            if not raw.startswith((" ", "\t")):
                m = _YARN_HEADER_RE.match(raw)
                current_spec = m.group("spec") if m else None
            elif current_spec is not None:
                vm = _YARN_VERSION_RE.match(raw)
                if vm:
                    name = _yarn_name_from_spec(current_spec)
                    version = vm.group(1)
                    if name and version and (name, version) not in seen:
                        seen.add((name, version))
                        components.append({
                            "type": "library",
                            "name": name,
                            "version": version,
                            "purl": f"pkg:npm/{name}@{version}",
                            "properties": [{"name": "hecate:source-file", "value": rel_path}],
                        })
                    current_spec = None  # consume until next header

    return components


# ---------------------------------------------------------------------------
# pnpm-lock.yaml
# ---------------------------------------------------------------------------


def _pnpm_name_and_version(key: str) -> tuple[str, str] | None:
    """Parse a pnpm lockfile `packages` key into (name, version).

    Key formats across pnpm versions:
      /@babel/core@7.12.3(peer)        — v9+
      /@babel/core/7.12.3               — v6
      /lodash@4.17.21
      /lodash/4.17.21
    """
    if not key.startswith("/"):
        return None
    body = key[1:]
    # Strip peer-dep suffix "(peer-a@1,peer-b@2)" or "_peer@1"
    paren = body.find("(")
    if paren >= 0:
        body = body[:paren]
    underscore = body.find("_")
    if underscore >= 0:
        body = body[:underscore]

    # Try the `name@version` split first (v9+)
    if body.startswith("@"):
        # @scope/name@version or @scope/name/version
        at = body.find("@", 1)
        slash = body.rfind("/")
        if at > 0 and (slash < 0 or at > slash):
            return body[:at], body[at + 1:]
        if slash > 0:
            return body[:slash], body[slash + 1:]
        return None

    at = body.find("@")
    slash = body.rfind("/")
    if at > 0 and (slash < 0 or at > slash):
        return body[:at], body[at + 1:]
    if slash > 0:
        return body[:slash], body[slash + 1:]
    return None


def parse_pnpm_lock_yaml(source_dir: str) -> list[dict[str, Any]]:
    """Extract resolved dependencies from pnpm-lock.yaml."""
    root = Path(source_dir)
    components: list[dict[str, Any]] = []

    for pl_path in root.rglob("pnpm-lock.yaml"):
        if _should_skip(pl_path):
            continue
        try:
            data = yaml.safe_load(pl_path.read_text(errors="replace"))
        except (OSError, yaml.YAMLError):
            continue
        if not isinstance(data, dict):
            continue

        rel_path = str(pl_path.relative_to(root))
        seen: set[tuple[str, str]] = set()

        packages = data.get("packages")
        if isinstance(packages, dict):
            for key, entry in packages.items():
                if not isinstance(key, str):
                    continue
                # pnpm v9+ sometimes stores name/version inline on the entry
                name, version = "", ""
                if isinstance(entry, dict):
                    nm = entry.get("name")
                    ver = entry.get("version")
                    if isinstance(nm, str) and isinstance(ver, str):
                        name, version = nm, ver
                if not name or not version:
                    parsed = _pnpm_name_and_version(key)
                    if parsed:
                        name, version = parsed
                if not name or not version or (name, version) in seen:
                    continue
                seen.add((name, version))
                components.append({
                    "type": "library",
                    "name": name,
                    "version": version,
                    "purl": f"pkg:npm/{name}@{version}",
                    "properties": [{"name": "hecate:source-file", "value": rel_path}],
                })

    return components


# ---------------------------------------------------------------------------
# Python: requirements.txt
# ---------------------------------------------------------------------------

_REQ_LINE_RE = re.compile(
    r"^([a-zA-Z0-9][a-zA-Z0-9._-]*)(?:\[.*?\])?\s*(?:(==|>=|~=|<=|!=|>|<|===)\s*([^\s,;#]+))?",
)


def parse_requirements_txt(source_dir: str) -> list[dict[str, Any]]:
    """Extract pip dependencies from requirements*.txt files."""
    root = Path(source_dir)
    components: list[dict[str, Any]] = []

    for req_path in root.rglob("requirements*.txt"):
        if _should_skip(req_path):
            continue
        try:
            content = req_path.read_text(errors="replace")
        except OSError:
            continue

        rel_path = str(req_path.relative_to(root))
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "-", "git+", "http")):
                continue
            m = _REQ_LINE_RE.match(line)
            if not m:
                continue
            name = m.group(1)
            version = m.group(3) or ""
            purl = f"pkg:pypi/{name.lower()}@{version}" if version else f"pkg:pypi/{name.lower()}"
            components.append(_lib_component(name, version, purl, rel_path))

    return components


# ---------------------------------------------------------------------------
# Python: pyproject.toml (PEP 621 + Poetry)
# ---------------------------------------------------------------------------

_PEP508_RE = re.compile(r"^([a-zA-Z0-9][a-zA-Z0-9._-]*)(?:\[.*?\])?\s*(?:(==|>=|~=|<=|!=|>|<)\s*([^\s,;]+))?")


def parse_pyproject_toml(source_dir: str) -> list[dict[str, Any]]:
    """Extract Python dependencies from pyproject.toml (PEP 621 + Poetry)."""
    root = Path(source_dir)
    components: list[dict[str, Any]] = []

    for pp_path in root.rglob("pyproject.toml"):
        if _should_skip(pp_path):
            continue
        try:
            data = tomllib.loads(pp_path.read_text(errors="replace"))
        except (OSError, tomllib.TOMLDecodeError):
            continue

        rel_path = str(pp_path.relative_to(root))

        # PEP 621: [project] dependencies
        project = data.get("project", {})
        for dep in project.get("dependencies", []):
            if isinstance(dep, str):
                m = _PEP508_RE.match(dep)
                if m:
                    name, version = m.group(1), m.group(3) or ""
                    purl = f"pkg:pypi/{name.lower()}@{version}" if version else f"pkg:pypi/{name.lower()}"
                    components.append(_lib_component(name, version, purl, rel_path))

        # PEP 621: optional-dependencies
        for group_deps in (project.get("optional-dependencies") or {}).values():
            if isinstance(group_deps, list):
                for dep in group_deps:
                    if isinstance(dep, str):
                        m = _PEP508_RE.match(dep)
                        if m:
                            name, version = m.group(1), m.group(3) or ""
                            purl = f"pkg:pypi/{name.lower()}@{version}" if version else f"pkg:pypi/{name.lower()}"
                            components.append(_lib_component(name, version, purl, rel_path))

        # Poetry: [tool.poetry.dependencies] + [tool.poetry.dev-dependencies]
        poetry = data.get("tool", {}).get("poetry", {})
        for section in ("dependencies", "dev-dependencies", "group"):
            deps = poetry.get(section, {})
            if isinstance(deps, dict):
                # Handle poetry groups: [tool.poetry.group.dev.dependencies]
                if section == "group":
                    for group_data in deps.values():
                        if isinstance(group_data, dict):
                            for dep_name, dep_spec in group_data.get("dependencies", {}).items():
                                if dep_name.lower() == "python":
                                    continue
                                version = _poetry_version(dep_spec)
                                purl = f"pkg:pypi/{dep_name.lower()}@{version}" if version else f"pkg:pypi/{dep_name.lower()}"
                                components.append(_lib_component(dep_name, version, purl, rel_path))
                else:
                    for dep_name, dep_spec in deps.items():
                        if dep_name.lower() == "python":
                            continue
                        version = _poetry_version(dep_spec)
                        purl = f"pkg:pypi/{dep_name.lower()}@{version}" if version else f"pkg:pypi/{dep_name.lower()}"
                        components.append(_lib_component(dep_name, version, purl, rel_path))

    return components


def _poetry_version(spec: Any) -> str:
    """Extract version from a Poetry dependency spec (string or dict)."""
    if isinstance(spec, str):
        return _extract_version(spec) if spec != "*" else ""
    if isinstance(spec, dict):
        v = spec.get("version", "")
        return _extract_version(v) if v and v != "*" else ""
    return ""


# ---------------------------------------------------------------------------
# Python: Pipfile
# ---------------------------------------------------------------------------

def parse_pipfile(source_dir: str) -> list[dict[str, Any]]:
    """Extract dependencies from Pipfile."""
    root = Path(source_dir)
    components: list[dict[str, Any]] = []

    for pf_path in root.rglob("Pipfile"):
        if _should_skip(pf_path):
            continue
        try:
            data = tomllib.loads(pf_path.read_text(errors="replace"))
        except (OSError, tomllib.TOMLDecodeError):
            continue

        rel_path = str(pf_path.relative_to(root))
        for section in ("packages", "dev-packages"):
            deps = data.get(section, {})
            if not isinstance(deps, dict):
                continue
            for dep_name, dep_spec in deps.items():
                version = ""
                if isinstance(dep_spec, str) and dep_spec != "*":
                    version = _extract_version(dep_spec)
                elif isinstance(dep_spec, dict):
                    v = dep_spec.get("version", "")
                    if v and v != "*":
                        version = _extract_version(v)
                purl = f"pkg:pypi/{dep_name.lower()}@{version}" if version else f"pkg:pypi/{dep_name.lower()}"
                components.append(_lib_component(dep_name, version, purl, rel_path))

    return components


# ---------------------------------------------------------------------------
# Python: Pipfile.lock (pipenv), poetry.lock, uv.lock
# ---------------------------------------------------------------------------


def parse_pipfile_lock(source_dir: str) -> list[dict[str, Any]]:
    """Extract resolved versions from Pipfile.lock (includes transitive deps)."""
    root = Path(source_dir)
    components: list[dict[str, Any]] = []

    for pl_path in root.rglob("Pipfile.lock"):
        if _should_skip(pl_path):
            continue
        try:
            data = json.loads(pl_path.read_text(errors="replace"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        rel_path = str(pl_path.relative_to(root))
        seen: set[tuple[str, str]] = set()
        for section in ("default", "develop"):
            deps = data.get(section)
            if not isinstance(deps, dict):
                continue
            for dep_name, dep_entry in deps.items():
                if not isinstance(dep_name, str) or not isinstance(dep_entry, dict):
                    continue
                version = dep_entry.get("version", "")
                if isinstance(version, str) and version.startswith("=="):
                    version = version[2:].strip()
                if not version or not isinstance(version, str):
                    continue
                key = (dep_name.lower(), version)
                if key in seen:
                    continue
                seen.add(key)
                purl = f"pkg:pypi/{dep_name.lower()}@{version}"
                components.append(_lib_component(dep_name, version, purl, rel_path))

    return components


def parse_poetry_lock(source_dir: str) -> list[dict[str, Any]]:
    """Extract resolved versions from poetry.lock (includes transitive deps)."""
    root = Path(source_dir)
    components: list[dict[str, Any]] = []

    for pl_path in root.rglob("poetry.lock"):
        if _should_skip(pl_path):
            continue
        try:
            data = tomllib.loads(pl_path.read_text(errors="replace"))
        except (OSError, tomllib.TOMLDecodeError):
            continue
        rel_path = str(pl_path.relative_to(root))
        packages = data.get("package")
        if not isinstance(packages, list):
            continue
        seen: set[tuple[str, str]] = set()
        for pkg in packages:
            if not isinstance(pkg, dict):
                continue
            name = pkg.get("name")
            version = pkg.get("version")
            if not isinstance(name, str) or not isinstance(version, str) or not name or not version:
                continue
            key = (name.lower(), version)
            if key in seen:
                continue
            seen.add(key)
            purl = f"pkg:pypi/{name.lower()}@{version}"
            components.append(_lib_component(name, version, purl, rel_path))

    return components


def parse_uv_lock(source_dir: str) -> list[dict[str, Any]]:
    """Extract resolved versions from uv.lock (astral-sh/uv, TOML; same shape as poetry.lock)."""
    root = Path(source_dir)
    components: list[dict[str, Any]] = []

    for ul_path in root.rglob("uv.lock"):
        if _should_skip(ul_path):
            continue
        try:
            data = tomllib.loads(ul_path.read_text(errors="replace"))
        except (OSError, tomllib.TOMLDecodeError):
            continue
        rel_path = str(ul_path.relative_to(root))
        packages = data.get("package")
        if not isinstance(packages, list):
            continue
        seen: set[tuple[str, str]] = set()
        for pkg in packages:
            if not isinstance(pkg, dict):
                continue
            name = pkg.get("name")
            version = pkg.get("version")
            if not isinstance(name, str) or not isinstance(version, str) or not name or not version:
                continue
            key = (name.lower(), version)
            if key in seen:
                continue
            seen.add(key)
            purl = f"pkg:pypi/{name.lower()}@{version}"
            components.append(_lib_component(name, version, purl, rel_path))

    return components


# ---------------------------------------------------------------------------
# Python: setup.cfg
# ---------------------------------------------------------------------------

def parse_setup_cfg(source_dir: str) -> list[dict[str, Any]]:
    """Extract dependencies from setup.cfg [options] install_requires."""
    root = Path(source_dir)
    components: list[dict[str, Any]] = []

    for sc_path in root.rglob("setup.cfg"):
        if _should_skip(sc_path):
            continue
        try:
            content = sc_path.read_text(errors="replace")
        except OSError:
            continue

        rel_path = str(sc_path.relative_to(root))
        # Extract install_requires block (may span multiple indented lines)
        m = re.search(r"install_requires\s*=\s*\n((?:\s+.+\n)*)", content)
        if not m:
            continue
        for line in m.group(1).splitlines():
            line = line.strip()
            if not line:
                continue
            pm = _PEP508_RE.match(line)
            if pm:
                name, version = pm.group(1), pm.group(3) or ""
                purl = f"pkg:pypi/{name.lower()}@{version}" if version else f"pkg:pypi/{name.lower()}"
                components.append(_lib_component(name, version, purl, rel_path))

    return components


# ---------------------------------------------------------------------------
# Go: go.mod
# ---------------------------------------------------------------------------

_GO_REQUIRE_RE = re.compile(r"^\s*(\S+)\s+(v[\d.]+\S*)", re.MULTILINE)


def parse_go_mod(source_dir: str) -> list[dict[str, Any]]:
    """Extract Go module dependencies from go.mod."""
    root = Path(source_dir)
    components: list[dict[str, Any]] = []

    for gm_path in root.rglob("go.mod"):
        if _should_skip(gm_path):
            continue
        try:
            content = gm_path.read_text(errors="replace")
        except OSError:
            continue

        rel_path = str(gm_path.relative_to(root))

        # Extract require blocks and single require lines
        # Remove replace/exclude blocks first
        clean = re.sub(r"(?:replace|exclude)\s*\(.*?\)", "", content, flags=re.DOTALL)
        # Find require blocks
        for block in re.finditer(r"require\s*\((.*?)\)", clean, re.DOTALL):
            for m in _GO_REQUIRE_RE.finditer(block.group(1)):
                mod_path, version = m.group(1), m.group(2)
                purl = f"pkg:golang/{mod_path}@{version}"
                components.append(_lib_component(mod_path, version, purl, rel_path))
        # Single-line require
        for m in re.finditer(r"^\s*require\s+(\S+)\s+(v[\d.]+\S*)", clean, re.MULTILINE):
            mod_path, version = m.group(1), m.group(2)
            purl = f"pkg:golang/{mod_path}@{version}"
            components.append(_lib_component(mod_path, version, purl, rel_path))

    return components


# ---------------------------------------------------------------------------
# Rust: Cargo.toml
# ---------------------------------------------------------------------------

def parse_cargo_toml(source_dir: str) -> list[dict[str, Any]]:
    """Extract Rust crate dependencies from Cargo.toml."""
    root = Path(source_dir)
    components: list[dict[str, Any]] = []

    for ct_path in root.rglob("Cargo.toml"):
        if _should_skip(ct_path):
            continue
        try:
            data = tomllib.loads(ct_path.read_text(errors="replace"))
        except (OSError, tomllib.TOMLDecodeError):
            continue

        rel_path = str(ct_path.relative_to(root))
        for section in ("dependencies", "dev-dependencies", "build-dependencies"):
            deps = data.get(section, {})
            if not isinstance(deps, dict):
                continue
            for crate_name, crate_spec in deps.items():
                version = ""
                if isinstance(crate_spec, str):
                    version = _extract_version(crate_spec)
                elif isinstance(crate_spec, dict):
                    v = crate_spec.get("version", "")
                    if v:
                        version = _extract_version(v)
                purl = f"pkg:cargo/{crate_name}@{version}" if version else f"pkg:cargo/{crate_name}"
                components.append(_lib_component(crate_name, version, purl, rel_path))

    return components


def parse_cargo_lock(source_dir: str) -> list[dict[str, Any]]:
    """Extract resolved crate versions from Cargo.lock (includes transitive deps)."""
    root = Path(source_dir)
    components: list[dict[str, Any]] = []

    for cl_path in root.rglob("Cargo.lock"):
        if _should_skip(cl_path):
            continue
        try:
            data = tomllib.loads(cl_path.read_text(errors="replace"))
        except (OSError, tomllib.TOMLDecodeError):
            continue
        rel_path = str(cl_path.relative_to(root))
        packages = data.get("package")
        if not isinstance(packages, list):
            continue
        seen: set[tuple[str, str]] = set()
        for pkg in packages:
            if not isinstance(pkg, dict):
                continue
            name = pkg.get("name")
            version = pkg.get("version")
            if not isinstance(name, str) or not isinstance(version, str) or not name or not version:
                continue
            if (name, version) in seen:
                continue
            seen.add((name, version))
            components.append(_lib_component(name, version, f"pkg:cargo/{name}@{version}", rel_path))

    return components


# ---------------------------------------------------------------------------
# Ruby: Gemfile + Gemfile.lock
# ---------------------------------------------------------------------------

_GEMFILE_RE = re.compile(r"""^\s*gem\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?""", re.MULTILINE)
_GEMLOCK_RE = re.compile(r"^\s{4}(\S+)\s+\(([^)]+)\)", re.MULTILINE)


def parse_gemfiles(source_dir: str) -> list[dict[str, Any]]:
    """Extract Ruby gem dependencies from Gemfile.lock (preferred) or Gemfile."""
    root = Path(source_dir)
    components: list[dict[str, Any]] = []

    for gl_path in root.rglob("Gemfile.lock"):
        if _should_skip(gl_path):
            continue
        try:
            content = gl_path.read_text(errors="replace")
        except OSError:
            continue
        rel_path = str(gl_path.relative_to(root))
        for m in _GEMLOCK_RE.finditer(content):
            name, version = m.group(1), m.group(2)
            components.append(_lib_component(name, version, f"pkg:gem/{name}@{version}", rel_path))

    # Fallback: Gemfile (only if no Gemfile.lock in same dir)
    for gf_path in root.rglob("Gemfile"):
        if _should_skip(gf_path):
            continue
        if (gf_path.parent / "Gemfile.lock").exists():
            continue
        try:
            content = gf_path.read_text(errors="replace")
        except OSError:
            continue
        rel_path = str(gf_path.relative_to(root))
        for m in _GEMFILE_RE.finditer(content):
            name = m.group(1)
            version = _extract_version(m.group(2)) if m.group(2) else ""
            purl = f"pkg:gem/{name}@{version}" if version else f"pkg:gem/{name}"
            components.append(_lib_component(name, version, purl, rel_path))

    return components


# ---------------------------------------------------------------------------
# PHP: composer.json + composer.lock
# ---------------------------------------------------------------------------

def parse_composer(source_dir: str) -> list[dict[str, Any]]:
    """Extract PHP dependencies from composer.lock (preferred) or composer.json."""
    root = Path(source_dir)
    components: list[dict[str, Any]] = []

    for cl_path in root.rglob("composer.lock"):
        if _should_skip(cl_path):
            continue
        try:
            data = json.loads(cl_path.read_text(errors="replace"))
        except (OSError, json.JSONDecodeError):
            continue
        rel_path = str(cl_path.relative_to(root))
        for pkg in data.get("packages", []) + data.get("packages-dev", []):
            if isinstance(pkg, dict):
                name = pkg.get("name", "")
                version = pkg.get("version", "").lstrip("v")
                if name:
                    purl = f"pkg:composer/{name}@{version}" if version else f"pkg:composer/{name}"
                    components.append(_lib_component(name, version, purl, rel_path))

    for cj_path in root.rglob("composer.json"):
        if _should_skip(cj_path):
            continue
        if (cj_path.parent / "composer.lock").exists():
            continue
        try:
            data = json.loads(cj_path.read_text(errors="replace"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        rel_path = str(cj_path.relative_to(root))
        for section in ("require", "require-dev"):
            deps = data.get(section, {})
            if not isinstance(deps, dict):
                continue
            for dep_name, dep_ver in deps.items():
                if dep_name.startswith("php") or dep_name.startswith("ext-"):
                    continue
                version = _extract_version(dep_ver) if isinstance(dep_ver, str) else ""
                purl = f"pkg:composer/{dep_name}@{version}" if version else f"pkg:composer/{dep_name}"
                components.append(_lib_component(dep_name, version, purl, rel_path))

    return components


# ---------------------------------------------------------------------------
# Java: pom.xml (Maven)
# ---------------------------------------------------------------------------

_MVN_NS = {"m": "http://maven.apache.org/POM/4.0.0"}


def parse_pom_xml(source_dir: str) -> list[dict[str, Any]]:
    """Extract Java/Kotlin dependencies from pom.xml (Maven)."""
    root = Path(source_dir)
    components: list[dict[str, Any]] = []

    for pom_path in root.rglob("pom.xml"):
        if _should_skip(pom_path):
            continue
        try:
            tree = ET.parse(pom_path)  # noqa: S314
        except (OSError, ET.ParseError):
            continue

        rel_path = str(pom_path.relative_to(root))
        xml_root = tree.getroot()

        # Collect properties for variable resolution
        props: dict[str, str] = {}
        for ns_prefix in ("m:", ""):
            for prop_el in xml_root.findall(f".//{ns_prefix}properties/*", _MVN_NS if ns_prefix else {}):
                tag = prop_el.tag.split("}")[-1] if "}" in prop_el.tag else prop_el.tag
                if prop_el.text:
                    props[tag] = prop_el.text.strip()

        # Find all <dependency> elements (with and without namespace)
        dep_elements = xml_root.findall(".//m:dependency", _MVN_NS)
        dep_elements += xml_root.findall(".//dependency")

        for dep in dep_elements:
            group_id = _xml_text(dep, "groupId", _MVN_NS) or _xml_text(dep, "groupId", {})
            artifact_id = _xml_text(dep, "artifactId", _MVN_NS) or _xml_text(dep, "artifactId", {})
            version = _xml_text(dep, "version", _MVN_NS) or _xml_text(dep, "version", {})

            if not group_id or not artifact_id:
                continue
            # Resolve ${property} references
            if version and version.startswith("${") and version.endswith("}"):
                prop_name = version[2:-1]
                version = props.get(prop_name, version)
            if not version or version.startswith("${"):
                version = ""

            purl = f"pkg:maven/{group_id}/{artifact_id}@{version}" if version else f"pkg:maven/{group_id}/{artifact_id}"
            components.append(_lib_component(f"{group_id}:{artifact_id}", version, purl, rel_path))

    return components


def _xml_text(parent: ET.Element, tag: str, ns: dict) -> str:
    """Get text content of a child element, with optional namespace."""
    if ns:
        el = parent.find(f"m:{tag}", ns)
    else:
        el = parent.find(tag)
    return el.text.strip() if el is not None and el.text else ""


# ---------------------------------------------------------------------------
# Java/Kotlin: build.gradle / build.gradle.kts
# ---------------------------------------------------------------------------

_GRADLE_DEP_RE = re.compile(
    r"""(?:implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly|annotationProcessor|kapt)\s*"""
    r"""[('"]([^:'"]+):([^:'"]+):([^'")\s]+)""",
)


def parse_gradle(source_dir: str) -> list[dict[str, Any]]:
    """Extract dependencies from build.gradle and build.gradle.kts files."""
    root = Path(source_dir)
    components: list[dict[str, Any]] = []

    for gf_path in list(root.rglob("build.gradle")) + list(root.rglob("build.gradle.kts")):
        if _should_skip(gf_path):
            continue
        try:
            content = gf_path.read_text(errors="replace")
        except OSError:
            continue
        rel_path = str(gf_path.relative_to(root))
        for m in _GRADLE_DEP_RE.finditer(content):
            group_id, artifact_id, version = m.group(1), m.group(2), m.group(3)
            if version.startswith("$"):
                version = ""
            purl = f"pkg:maven/{group_id}/{artifact_id}@{version}" if version else f"pkg:maven/{group_id}/{artifact_id}"
            components.append(_lib_component(f"{group_id}:{artifact_id}", version, purl, rel_path))

    return components


_GRADLE_LOCK_RE = re.compile(r"^([^:\s#]+):([^:\s]+):([^=\s]+)=", re.MULTILINE)


def parse_gradle_lockfile(source_dir: str) -> list[dict[str, Any]]:
    """Extract resolved Maven coordinates from gradle.lockfile (Gradle dependency locking)."""
    root = Path(source_dir)
    components: list[dict[str, Any]] = []

    for gl_path in root.rglob("gradle.lockfile"):
        if _should_skip(gl_path):
            continue
        try:
            content = gl_path.read_text(errors="replace")
        except OSError:
            continue
        rel_path = str(gl_path.relative_to(root))
        seen: set[tuple[str, str]] = set()
        for m in _GRADLE_LOCK_RE.finditer(content):
            group_id, artifact_id, version = m.group(1), m.group(2), m.group(3)
            key = (f"{group_id}:{artifact_id}", version)
            if key in seen:
                continue
            seen.add(key)
            purl = f"pkg:maven/{group_id}/{artifact_id}@{version}"
            components.append(_lib_component(f"{group_id}:{artifact_id}", version, purl, rel_path))

    return components


# ---------------------------------------------------------------------------
# Go: go.sum (transitive resolution; go.mod has direct deps)
# ---------------------------------------------------------------------------

_GOSUM_LINE_RE = re.compile(r"^(\S+)\s+(v\S+?)(?:/go\.mod)?\s+h1:\S+", re.MULTILINE)


def parse_go_sum(source_dir: str) -> list[dict[str, Any]]:
    """Extract resolved module versions from go.sum.

    Each module appears twice in go.sum (once as the zip, once as `/go.mod`).
    We deduplicate on (module, version).
    """
    root = Path(source_dir)
    components: list[dict[str, Any]] = []

    for gs_path in root.rglob("go.sum"):
        if _should_skip(gs_path):
            continue
        try:
            content = gs_path.read_text(errors="replace")
        except OSError:
            continue
        rel_path = str(gs_path.relative_to(root))
        seen: set[tuple[str, str]] = set()
        for m in _GOSUM_LINE_RE.finditer(content):
            mod_path, version = m.group(1), m.group(2)
            if (mod_path, version) in seen:
                continue
            seen.add((mod_path, version))
            purl = f"pkg:golang/{mod_path}@{version}"
            components.append(_lib_component(mod_path, version, purl, rel_path))

    return components


# ---------------------------------------------------------------------------
# npm: bun.lock (Bun's text lockfile; bun.lockb is binary, handled by syft)
# ---------------------------------------------------------------------------


def parse_bun_lock(source_dir: str) -> list[dict[str, Any]]:
    """Extract resolved npm versions from bun.lock (Bun's text lockfile, JSONC format).

    bun.lock is "JSON with comments + trailing commas". We strip line comments
    and trailing commas, then json.loads. Schema:
      {"lockfileVersion":0,"packages":{"<name>":["<name>@<version>", ...], ...}}
    """
    root = Path(source_dir)
    components: list[dict[str, Any]] = []

    for bl_path in root.rglob("bun.lock"):
        if _should_skip(bl_path):
            continue
        try:
            raw = bl_path.read_text(errors="replace")
        except OSError:
            continue
        # Strip JSONC line comments (only at line start, not inside URL strings)
        # and trailing commas, then json.loads.
        stripped = re.sub(r"(?m)^\s*//[^\n]*$", "", raw)
        stripped = re.sub(r",(\s*[}\]])", r"\1", stripped)
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict):
            continue
        rel_path = str(bl_path.relative_to(root))
        packages = data.get("packages")
        if not isinstance(packages, dict):
            continue
        seen: set[tuple[str, str]] = set()
        for _key, entry in packages.items():
            # Entry is a list: ["pkgname@version", "registry-url", {deps}, "integrity"]
            if not isinstance(entry, list) or not entry:
                continue
            spec = entry[0]
            if not isinstance(spec, str):
                continue
            # Parse "name@version" or "@scope/name@version"
            if spec.startswith("@"):
                at = spec.find("@", 1)
                if at <= 0:
                    continue
                name, version = spec[:at], spec[at + 1:]
            else:
                at = spec.find("@")
                if at <= 0:
                    continue
                name, version = spec[:at], spec[at + 1:]
            if not name or not version or (name, version) in seen:
                continue
            seen.add((name, version))
            purl = f"pkg:npm/{name}@{version}"
            components.append({
                "type": "library",
                "name": name,
                "version": version,
                "purl": purl,
                "properties": [{"name": "hecate:source-file", "value": rel_path}],
            })

    return components


# ---------------------------------------------------------------------------
# C# / .NET: *.csproj + packages.config
# ---------------------------------------------------------------------------

def _collect_central_package_versions(root: Path) -> dict[str, str]:
    """Read every Directory.Packages.props (Central Package Management).

    Maps PackageVersion `Include` → `Version`. Resolved package versions are
    used by .csproj `<PackageReference>` elements that omit the Version attribute.
    """
    versions: dict[str, str] = {}
    for cpm_path in root.rglob("Directory.Packages.props"):
        if _should_skip(cpm_path):
            continue
        try:
            tree = ET.parse(cpm_path)  # noqa: S314
        except (OSError, ET.ParseError):
            continue
        for el in tree.iter():
            tag = el.tag.split("}")[-1] if "}" in el.tag else el.tag
            if tag == "PackageVersion":
                name = el.get("Include") or el.get("include") or ""
                version = el.get("Version") or el.get("version") or ""
                if name and version and name not in versions:
                    versions[name] = version
    return versions


def parse_dotnet(source_dir: str) -> list[dict[str, Any]]:
    """Extract NuGet dependencies from *.csproj, packages.config, packages.lock.json."""
    root = Path(source_dir)
    components: list[dict[str, Any]] = []
    cpm_versions = _collect_central_package_versions(root)

    # Modern .NET: *.csproj with <PackageReference>. Also handle *.fsproj/*.vbproj.
    for proj_glob in ("*.csproj", "*.fsproj", "*.vbproj"):
        for proj_path in root.rglob(proj_glob):
            if _should_skip(proj_path):
                continue
            try:
                tree = ET.parse(proj_path)  # noqa: S314
            except (OSError, ET.ParseError):
                continue
            rel_path = str(proj_path.relative_to(root))
            for pr in tree.iter():
                tag = pr.tag.split("}")[-1] if "}" in pr.tag else pr.tag
                if tag != "PackageReference":
                    continue
                name = pr.get("Include") or pr.get("include") or pr.get("Update") or ""
                if not name:
                    continue
                version = pr.get("Version") or pr.get("version") or ""
                if not version:
                    # Look for nested <Version> child (rare style)
                    for child in pr.iter():
                        ctag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                        if ctag == "Version" and child.text:
                            version = child.text.strip()
                            break
                if not version:
                    # Central Package Management: pull version from Directory.Packages.props
                    version = cpm_versions.get(name, "")
                purl = f"pkg:nuget/{name}@{version}" if version else f"pkg:nuget/{name}"
                components.append(_lib_component(name, version, purl, rel_path))

    # Legacy .NET: packages.config
    for pc_path in root.rglob("packages.config"):
        if _should_skip(pc_path):
            continue
        try:
            tree = ET.parse(pc_path)  # noqa: S314
        except (OSError, ET.ParseError):
            continue
        rel_path = str(pc_path.relative_to(root))
        for pkg in tree.iter("package"):
            name = pkg.get("id", "")
            version = pkg.get("version", "")
            if name:
                purl = f"pkg:nuget/{name}@{version}" if version else f"pkg:nuget/{name}"
                components.append(_lib_component(name, version, purl, rel_path))

    # NuGet lockfile: packages.lock.json (resolved transitive dependencies).
    # Schema: {"version":1,"dependencies":{"<TFM>":{"<PkgId>":{"resolved":"x.y.z",...}}}}
    for lock_path in root.rglob("packages.lock.json"):
        if _should_skip(lock_path):
            continue
        try:
            data = json.loads(lock_path.read_text(errors="replace"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        rel_path = str(lock_path.relative_to(root))
        deps_by_tfm = data.get("dependencies")
        if not isinstance(deps_by_tfm, dict):
            continue
        seen: set[tuple[str, str]] = set()
        for tfm_deps in deps_by_tfm.values():
            if not isinstance(tfm_deps, dict):
                continue
            for pkg_name, pkg_entry in tfm_deps.items():
                if not isinstance(pkg_name, str) or not isinstance(pkg_entry, dict):
                    continue
                version = pkg_entry.get("resolved") or pkg_entry.get("requested") or ""
                if not isinstance(version, str) or not version:
                    continue
                if (pkg_name, version) in seen:
                    continue
                seen.add((pkg_name, version))
                purl = f"pkg:nuget/{pkg_name}@{version}"
                components.append(_lib_component(pkg_name, version, purl, rel_path))

    # NuGet restore output: project.assets.json (transitive graph).
    # Useful when no packages.lock.json is present but `dotnet restore` ran.
    for assets_path in root.rglob("project.assets.json"):
        if _should_skip(assets_path):
            continue
        try:
            data = json.loads(assets_path.read_text(errors="replace"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        rel_path = str(assets_path.relative_to(root))
        libraries = data.get("libraries")
        if not isinstance(libraries, dict):
            continue
        seen2: set[tuple[str, str]] = set()
        for key, entry in libraries.items():
            # Keys look like "Newtonsoft.Json/13.0.3"; type "package" only
            if not isinstance(key, str) or "/" not in key:
                continue
            if isinstance(entry, dict) and entry.get("type") and entry["type"] != "package":
                continue
            name, _, version = key.partition("/")
            if not name or not version or (name, version) in seen2:
                continue
            seen2.add((name, version))
            purl = f"pkg:nuget/{name}@{version}"
            components.append(_lib_component(name, version, purl, rel_path))

    return components


# ---------------------------------------------------------------------------
# Swift: Package.resolved
# ---------------------------------------------------------------------------

def parse_swift(source_dir: str) -> list[dict[str, Any]]:
    """Extract Swift package dependencies from Package.resolved."""
    root = Path(source_dir)
    components: list[dict[str, Any]] = []

    for pr_path in root.rglob("Package.resolved"):
        if _should_skip(pr_path):
            continue
        try:
            data = json.loads(pr_path.read_text(errors="replace"))
        except (OSError, json.JSONDecodeError):
            continue
        rel_path = str(pr_path.relative_to(root))

        # v2/v3 format
        pins = data.get("pins", [])
        if not pins:
            # v1 format
            obj = data.get("object", {})
            pins = obj.get("pins", [])

        for pin in pins:
            if not isinstance(pin, dict):
                continue
            name = pin.get("identity") or pin.get("package", "")
            state = pin.get("state", {})
            version = state.get("version", "") if isinstance(state, dict) else ""
            if name:
                purl = f"pkg:swift/{name}@{version}" if version else f"pkg:swift/{name}"
                components.append(_lib_component(name, version or "", purl, rel_path))

    return components


# ---------------------------------------------------------------------------
# Elixir: mix.lock
# ---------------------------------------------------------------------------

_MIX_LOCK_RE = re.compile(r'"([^"]+)":\s*\{\s*:hex,\s*:\w+,\s*"([^"]+)"')


def parse_mix(source_dir: str) -> list[dict[str, Any]]:
    """Extract Elixir/Erlang dependencies from mix.lock."""
    root = Path(source_dir)
    components: list[dict[str, Any]] = []

    for ml_path in root.rglob("mix.lock"):
        if _should_skip(ml_path):
            continue
        try:
            content = ml_path.read_text(errors="replace")
        except OSError:
            continue
        rel_path = str(ml_path.relative_to(root))
        for m in _MIX_LOCK_RE.finditer(content):
            name, version = m.group(1), m.group(2)
            components.append(_lib_component(name, version, f"pkg:hex/{name}@{version}", rel_path))

    return components


# ---------------------------------------------------------------------------
# Dart/Flutter: pubspec.yaml + pubspec.lock
# ---------------------------------------------------------------------------

def parse_pubspec(source_dir: str) -> list[dict[str, Any]]:
    """Extract Dart/Flutter dependencies from pubspec.lock (preferred) or pubspec.yaml."""
    root = Path(source_dir)
    components: list[dict[str, Any]] = []

    for pl_path in root.rglob("pubspec.lock"):
        if _should_skip(pl_path):
            continue
        try:
            data = yaml.safe_load(pl_path.read_text(errors="replace"))
        except (OSError, yaml.YAMLError):
            continue
        if not isinstance(data, dict):
            continue
        rel_path = str(pl_path.relative_to(root))
        packages = data.get("packages", {})
        if isinstance(packages, dict):
            for pkg_name, pkg_data in packages.items():
                if isinstance(pkg_data, dict):
                    version = pkg_data.get("version", "")
                    purl = f"pkg:pub/{pkg_name}@{version}" if version else f"pkg:pub/{pkg_name}"
                    components.append(_lib_component(pkg_name, version or "", purl, rel_path))

    for py_path in root.rglob("pubspec.yaml"):
        if _should_skip(py_path):
            continue
        if (py_path.parent / "pubspec.lock").exists():
            continue
        try:
            data = yaml.safe_load(py_path.read_text(errors="replace"))
        except (OSError, yaml.YAMLError):
            continue
        if not isinstance(data, dict):
            continue
        rel_path = str(py_path.relative_to(root))
        for section in ("dependencies", "dev_dependencies"):
            deps = data.get(section, {})
            if not isinstance(deps, dict):
                continue
            for dep_name, dep_spec in deps.items():
                # Skip SDK deps
                if isinstance(dep_spec, dict) and "sdk" in dep_spec:
                    continue
                version = ""
                if isinstance(dep_spec, str) and dep_spec not in ("any", ""):
                    version = _extract_version(dep_spec)
                purl = f"pkg:pub/{dep_name}@{version}" if version else f"pkg:pub/{dep_name}"
                components.append(_lib_component(dep_name, version, purl, rel_path))

    return components


# ---------------------------------------------------------------------------
# CocoaPods: Podfile.lock
# ---------------------------------------------------------------------------

_PODLOCK_RE = re.compile(r"^\s+-\s+(\S+)\s+\(([^)]+)\)", re.MULTILINE)


def parse_cocoapods(source_dir: str) -> list[dict[str, Any]]:
    """Extract CocoaPods dependencies from Podfile.lock."""
    root = Path(source_dir)
    components: list[dict[str, Any]] = []

    for pl_path in root.rglob("Podfile.lock"):
        if _should_skip(pl_path):
            continue
        try:
            content = pl_path.read_text(errors="replace")
        except OSError:
            continue
        rel_path = str(pl_path.relative_to(root))
        for m in _PODLOCK_RE.finditer(content):
            name, version = m.group(1), m.group(2)
            components.append(_lib_component(name, version, f"pkg:cocoapods/{name}@{version}", rel_path))

    return components


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_analysis(source_dir: str) -> dict[str, Any]:
    """Run all parsers and return a CycloneDX JSON envelope."""
    all_components: list[dict[str, Any]] = []

    # Container infrastructure
    all_components.extend(parse_dockerfiles(source_dir))
    all_components.extend(parse_compose_files(source_dir))

    # JavaScript / Node.js — prefer lockfiles (resolved versions), fall back
    # to manifest-only directories. `_filter_and_merge_sbom` on the backend
    # collapses duplicates by name+version, so parsing both is safe.
    all_components.extend(parse_package_jsons(source_dir))
    all_components.extend(parse_package_lock_json(source_dir))
    all_components.extend(parse_yarn_lock(source_dir))
    all_components.extend(parse_pnpm_lock_yaml(source_dir))
    all_components.extend(parse_bun_lock(source_dir))

    # Python
    all_components.extend(parse_requirements_txt(source_dir))
    all_components.extend(parse_pyproject_toml(source_dir))
    all_components.extend(parse_pipfile(source_dir))
    all_components.extend(parse_pipfile_lock(source_dir))
    all_components.extend(parse_poetry_lock(source_dir))
    all_components.extend(parse_uv_lock(source_dir))
    all_components.extend(parse_setup_cfg(source_dir))

    # Go
    all_components.extend(parse_go_mod(source_dir))
    all_components.extend(parse_go_sum(source_dir))

    # Rust
    all_components.extend(parse_cargo_toml(source_dir))
    all_components.extend(parse_cargo_lock(source_dir))

    # Ruby
    all_components.extend(parse_gemfiles(source_dir))

    # PHP
    all_components.extend(parse_composer(source_dir))

    # Java / Kotlin
    all_components.extend(parse_pom_xml(source_dir))
    all_components.extend(parse_gradle(source_dir))
    all_components.extend(parse_gradle_lockfile(source_dir))

    # C# / .NET
    all_components.extend(parse_dotnet(source_dir))

    # Swift
    all_components.extend(parse_swift(source_dir))

    # Elixir
    all_components.extend(parse_mix(source_dir))

    # Dart / Flutter
    all_components.extend(parse_pubspec(source_dir))

    # CocoaPods
    all_components.extend(parse_cocoapods(source_dir))

    # Deduplicate by purl (more precise than name:version)
    seen: dict[str, dict[str, Any]] = {}
    for comp in all_components:
        key = comp.get("purl") or f"{comp['name']}:{comp.get('version', '')}"
        if key not in seen:
            seen[key] = comp

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": list(seen.values()),
    }
