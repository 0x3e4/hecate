"""Shape of the catalog relevance pipeline.

The ordering itself runs inside MongoDB, so these tests pin what the database is
asked to do: user input only ever reaches a regex as a literal, and a page is cut
after sorting.
"""
from __future__ import annotations

from app.repositories.asset_repository import relevance_pipeline


def _stages(keyword: str) -> list[dict]:
    return relevance_pipeline({"displayName": {"$regex": "x"}}, keyword, limit=25, offset=50)


def _regexes(pipeline: list[dict]) -> list[str]:
    branches = pipeline[1]["$addFields"]["_tier"]["$switch"]["branches"]
    return [branch["case"]["$regexMatch"]["regex"] for branch in branches[1:]]


def test_exact_name_ranks_above_prefix_word_and_contains() -> None:
    branches = _stages("wordpress")[1]["$addFields"]["_tier"]["$switch"]
    assert [branch["then"] for branch in branches["branches"]] == [0, 1, 2]
    assert branches["default"] == 3
    exact = branches["branches"][0]["case"]["$or"]
    assert {"$eq": ["$_id", "wordpress"]} in exact
    assert {"$eq": ["$normalizedKey", "wordpress"]} in exact


def test_keyword_reaches_regexes_only_as_a_literal() -> None:
    assert _regexes(_stages("a.*(b)")) == [r"^a\.\*\(b\)", r"\ba\.\*\(b\)"]


def test_keyword_length_is_bounded() -> None:
    assert len(_regexes(_stages("a" * 5000))[0]) <= 201


def test_page_is_cut_after_sorting() -> None:
    stages = [next(iter(stage)) for stage in _stages("nginx")]
    assert stages == ["$match", "$addFields", "$sort", "$skip", "$limit"]
    assert _stages("nginx")[3] == {"$skip": 50}
