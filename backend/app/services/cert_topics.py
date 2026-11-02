from __future__ import annotations

from typing import Any

# An advisory naming this many CVEs is a round-up (a distribution's kernel batch, a browser
# release). Merging through one would tie unrelated topics together over a shared CVE.
ROUNDUP_MIN_CVES = 20


def group_advisories(advisories: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """
    Splits advisories into topics and round-ups. A topic is every advisory connected
    through a shared CVE, so a third CERT naming a second CVE of the same flaw joins it.
    """
    focused = [a for a in advisories if len(a["cve_ids"]) < ROUNDUP_MIN_CVES]
    roundups = [a for a in advisories if len(a["cve_ids"]) >= ROUNDUP_MIN_CVES]

    parent = list(range(len(focused)))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    owner: dict[str, int] = {}
    for index, advisory in enumerate(focused):
        for cve_id in advisory["cve_ids"]:
            if cve_id in owner:
                parent[find(index)] = find(owner[cve_id])
            else:
                owner[cve_id] = index

    members: dict[int, list[dict[str, Any]]] = {}
    for index, advisory in enumerate(focused):
        members.setdefault(find(index), []).append(advisory)

    topics = [
        {
            "id": min(str(a["_id"]) for a in group),
            "advisories": sorted(group, key=lambda a: a["published"], reverse=True),
            "cve_ids": sorted({cve_id for a in group for cve_id in a["cve_ids"]}),
        }
        for group in members.values()
    ]
    topics.sort(key=lambda topic: topic["advisories"][0]["published"], reverse=True)
    roundups.sort(key=lambda advisory: advisory["published"], reverse=True)
    return topics, roundups
