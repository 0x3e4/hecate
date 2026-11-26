"""The inventory's per-item CVE list carries when each CVE last changed."""

from datetime import UTC, datetime

from app.services import inventory_service as module
from app.services.inventory_service import InventoryService


class _Repo:
    async def get(self, item_id):
        return {"_id": item_id, "vendor_slug": "graylog", "product_slug": "graylog", "version": "5.0.1"}


async def test_affected_vulnerabilities_carry_last_change(monkeypatch):
    changed = datetime(2026, 11, 20, 8, 30, tzinfo=UTC)

    async def fake_create():
        return object()

    async def fake_vulns_for_item(_repo, _key, *, limit):
        return [
            {"_id": "CVE-2026-1", "cvss": {"severity": "HIGH", "base_score": 7.5}, "last_change_at": changed},
            {"_id": "CVE-2026-2", "cvss": {"severity": "LOW", "base_score": 3.1}},
        ]

    monkeypatch.setattr(module.VulnerabilityRepository, "create", staticmethod(fake_create))
    monkeypatch.setattr(module, "vulns_for_item", fake_vulns_for_item)
    service = InventoryService()

    async def fake_get_repo():
        return _Repo()

    monkeypatch.setattr(service, "_get_repo", fake_get_repo)

    results = await service.vulns_affecting_item("item-1")

    assert [r.vuln_id for r in results] == ["CVE-2026-1", "CVE-2026-2"]
    dumped = results[0].model_dump(by_alias=True, mode="json")
    assert dumped["lastChangeAt"] == "2026-11-20T08:30:00Z"
    assert results[1].last_change_at is None
