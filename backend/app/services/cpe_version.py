"""The version a CPE 2.3 name stands for, pre-release included.

CPE keeps a pre-release out of the version field: Wazuh 5.0.0 beta 1 is
``cpe:2.3:a:wazuh:wazuh:5.0.0:beta1:*:...``, with ``beta1`` in the *update*
field. Read from the version field alone that is "5.0.0", the final release,
so an advisory about the betas flagged everyone on 5.0.0. Both the normalizer
(what lands in impactedProducts) and the inventory matcher (exact CPE pins)
read the version through here, so the two agree.

Only unambiguous pre-release tags are taken over. ``sp1``, ``update_123`` or
``p2`` mark releases *after* the base version; written as ``5.0.0-sp1`` the
matcher would sort them before it, so they are left as they were.
"""
from __future__ import annotations

import re

_WILDCARDS = {"", "*", "-", "ANY", "NA"}
_PRE_RELEASE_UPDATE = re.compile(r"^(?:alpha|beta|rc|pre|preview|dev)[._-]?\d*$", re.IGNORECASE)


def version_with_update(version: str | None, update: str | None) -> str | None:
    """``version`` with a pre-release ``update`` appended (``5.0.0`` + ``beta1`` → ``5.0.0-beta1``).

    None for a wildcard version; the version unchanged for any other update.
    """
    if version is None:
        return None
    base = version.replace("\\", "").strip()
    if base in _WILDCARDS:
        return None
    tag = (update or "").replace("\\", "").strip()
    if tag and tag not in _WILDCARDS and _PRE_RELEASE_UPDATE.match(tag):
        return f"{base}-{tag.lower()}"
    return base


def cpe_version(criteria: str | None) -> str | None:
    """The version of a ``cpe:2.3:`` name, or None for a wildcard / no CPE 2.3 name."""
    if not isinstance(criteria, str) or not criteria.startswith("cpe:2.3:"):
        return None
    parts = criteria.split(":")
    if len(parts) < 6:
        return None
    return version_with_update(parts[5], parts[6] if len(parts) > 6 else None)
