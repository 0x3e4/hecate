from __future__ import annotations

from typing import Any

# An advisory naming this many CVEs is a round-up (a distribution's kernel batch, a browser
# release). Merging through one would tie unrelated topics together over a shared CVE.
ROUNDUP_MIN_CVES = 20
# A community post is held to a much lower limit: a "patch these today" post with five CVEs
# is a list, not a topic.
COMMUNITY_TOPIC_MAX_CVES = 3

COMMUNITY = "community"


def is_community(advisory: dict[str, Any]) -> bool:
    return advisory.get("kind") == COMMUNITY


def _union(advisories: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """Groups of advisories connected through shared CVEs."""
    parent = list(range(len(advisories)))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    owner: dict[str, int] = {}
    for index, advisory in enumerate(advisories):
        for cve_id in advisory["cve_ids"]:
            if cve_id in owner:
                parent[find(index)] = find(owner[cve_id])
            else:
                owner[cve_id] = index

    members: dict[int, list[dict[str, Any]]] = {}
    for index, advisory in enumerate(advisories):
        members.setdefault(find(index), []).append(advisory)
    return list(members.values())


def group_advisories(advisories: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """
    Splits advisories into topics and round-ups. A topic is every CERT or vendor
    advisory connected through a shared CVE, so a third CERT naming a second CVE of
    the same flaw joins it.

    Community posts never connect topics: one post naming two flaws would otherwise
    merge them. A post joins every topic whose CVE it names, without adding its other
    CVEs; posts that touch no topic group among themselves. A post with more than
    ``COMMUNITY_TOPIC_MAX_CVES`` CVEs is a round-up.
    """
    anchors = [a for a in advisories if not is_community(a)]
    community = [a for a in advisories if is_community(a)]
    roundups = [a for a in anchors if len(a["cve_ids"]) >= ROUNDUP_MIN_CVES]
    roundups += [a for a in community if len(a["cve_ids"]) > COMMUNITY_TOPIC_MAX_CVES]

    groups = [
        {"anchors": group, "posts": [], "cve_ids": {cve for a in group for cve in a["cve_ids"]}}
        for group in _union([a for a in anchors if len(a["cve_ids"]) < ROUNDUP_MIN_CVES])
    ]
    topic_of: dict[str, int] = {cve: index for index, group in enumerate(groups) for cve in group["cve_ids"]}

    unattached: list[dict[str, Any]] = []
    for post in community:
        if len(post["cve_ids"]) > COMMUNITY_TOPIC_MAX_CVES:
            continue
        touched = sorted({topic_of[cve] for cve in post["cve_ids"] if cve in topic_of})
        for index in touched:
            groups[index]["posts"].append(post)
        if not touched:
            unattached.append(post)
    groups += [
        {"anchors": [], "posts": group, "cve_ids": {cve for a in group for cve in a["cve_ids"]}}
        for group in _union(unattached)
    ]

    def by_date(group: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return sorted(group, key=lambda a: a["published"], reverse=True)

    topics = [
        {
            # From the CERT and vendor advisories when there are any, so a post joining later keeps the id.
            "id": min(str(a["_id"]) for a in group["anchors"] or group["posts"]),
            "advisories": by_date([*group["anchors"], *group["posts"]]),
            "cve_ids": sorted(group["cve_ids"]),
        }
        for group in groups
    ]
    topics.sort(key=lambda topic: topic["advisories"][0]["published"], reverse=True)
    roundups.sort(key=lambda advisory: advisory["published"], reverse=True)
    return topics, roundups
