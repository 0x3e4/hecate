"""Hecate Analyzer — extracts components from Dockerfiles, docker-compose, and package.json."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

# ---------------------------------------------------------------------------
# Dockerfile parsing
# ---------------------------------------------------------------------------

_FROM_RE = re.compile(
    r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+?)(?:\s+AS\s+(\S+))?\s*$",
    re.IGNORECASE | re.MULTILINE,
)

_COPY_FROM_RE = re.compile(
    r"^\s*COPY\s+--from=(\S+)",
    re.IGNORECASE | re.MULTILINE,
)

_DOCKERFILE_GLOBS = ("Dockerfile", "Dockerfile.*", "*.dockerfile")


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

        # Track stage aliases so we can skip internal COPY --from= refs
        stage_aliases: set[str] = set()

        for match in _FROM_RE.finditer(content):
            image_ref = match.group(1)
            alias = match.group(2)
            if alias:
                stage_aliases.add(alias.lower())

            if image_ref.lower() == "scratch":
                continue

            name, version = _split_image_ref(image_ref)
            components.append(_image_to_component(name, version, rel_path))

        # COPY --from=<external_image> (not a build stage)
        for match in _COPY_FROM_RE.finditer(content):
            ref = match.group(1)
            # Skip numeric stage references (e.g. COPY --from=0)
            if ref.isdigit():
                continue
            if ref.lower() in stage_aliases:
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
            name, version = _split_image_ref(image.strip())
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
# Main entry point
# ---------------------------------------------------------------------------

def run_analysis(source_dir: str) -> dict[str, Any]:
    """Run all parsers and return a CycloneDX JSON envelope."""
    all_components: list[dict[str, Any]] = []
    all_components.extend(parse_dockerfiles(source_dir))
    all_components.extend(parse_compose_files(source_dir))
    all_components.extend(parse_package_jsons(source_dir))

    # Deduplicate by name:version
    seen: dict[str, dict[str, Any]] = {}
    for comp in all_components:
        key = f"{comp['name']}:{comp.get('version', '')}"
        if key not in seen:
            seen[key] = comp

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": list(seen.values()),
    }
