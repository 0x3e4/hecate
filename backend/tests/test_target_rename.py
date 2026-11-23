"""Renaming a scan target: the name survives the next scan's upsert, and its
scans carry the new name."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.models.scan import ScanTargetDocument
from app.repositories.scan_target_repository import ScanTargetRepository
from app.schemas.scan import TARGET_NAME_MAX_LENGTH, normalize_target_name
from app.services.scan_service import ScanService

from tests.fake_mongo import FakeCollection

TARGET_ID = "ghcr.io/0x3e4/hecate-docs"


def _doc(name: str = "hecate-docs") -> ScanTargetDocument:
    return ScanTargetDocument(target_id=TARGET_ID, type="container_image", name=name, scanners=["trivy"])


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("  Docs   site ", "Docs site"),
        ("Docs\x00\x07 site", "Docs site"),
        ("", None),
        ("   ", None),
        (None, None),
        (42, None),
        ("x" * TARGET_NAME_MAX_LENGTH, "x" * TARGET_NAME_MAX_LENGTH),
        ("x" * (TARGET_NAME_MAX_LENGTH + 1), None),
    ],
)
def test_normalize_target_name(value, expected):
    assert normalize_target_name(value) == expected


async def test_rename_survives_rescan_upsert():
    repo = ScanTargetRepository(FakeCollection())
    await repo.upsert(_doc())

    assert await repo.update_name(TARGET_ID, "Documentation site")
    # The next scan upserts the target with the name derived from its reference.
    await repo.upsert(_doc("hecate-docs"))

    stored = await repo.get(TARGET_ID)
    assert stored["name"] == "Documentation site"
    assert stored["name_custom"] is True


async def test_upsert_without_rename_takes_the_derived_name():
    repo = ScanTargetRepository(FakeCollection())
    await repo.upsert(_doc("old"))
    await repo.upsert(_doc("new"))

    stored = await repo.get(TARGET_ID)
    assert stored["name"] == "new"
    assert not stored.get("name_custom")


async def test_rename_unknown_target():
    repo = ScanTargetRepository(FakeCollection())
    assert not await repo.update_name("nope", "Name")


async def test_rename_target_updates_its_scans_only():
    targets = ScanTargetRepository(FakeCollection())
    await targets.upsert(_doc())
    scans = FakeCollection(
        [
            {"_id": "s1", "target_id": TARGET_ID, "target_name": "hecate-docs"},
            {"_id": "s2", "target_id": "other", "target_name": "other"},
        ]
    )
    service = ScanService.__new__(ScanService)
    service.target_repo = targets
    service.scan_repo = SimpleNamespace(collection=scans)

    assert await service.rename_target(TARGET_ID, "Docs")
    assert scans.by_id("s1")["target_name"] == "Docs"
    assert scans.by_id("s2")["target_name"] == "other"
