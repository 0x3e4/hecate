"""The sidebar's Documentation link comes from DOCS_URL, http(s) only."""
from __future__ import annotations

import pytest

from app.api.v1.config import public_docs_url


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://docs.hecate.pw", "https://docs.hecate.pw"),
        ("  http://docs.internal:8001/  ", "http://docs.internal:8001/"),
        ("", None),
        ("   ", None),
        ("javascript:alert(1)", None),
        ("file:///etc/passwd", None),
        ("docs.hecate.pw", None),
        ("https://", None),
    ],
)
def test_only_an_http_url_becomes_the_docs_link(value: str, expected: str | None) -> None:
    assert public_docs_url(value) == expected
