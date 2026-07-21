"""Tests for the insecure-default-secret startup guard and CORS scoping helper."""
from __future__ import annotations

from app.core.config import Settings


def _settings(**overrides) -> Settings:
    base = dict(environment="production", mongo_password=None)
    base.update(overrides)
    return Settings(**base)  # type: ignore[arg-type]


def test_production_like_detection():
    assert _settings(environment="production").is_production_like() is True
    assert _settings(environment="staging").is_production_like() is True
    assert _settings(environment="development").is_production_like() is False
    assert _settings(environment="dev").is_production_like() is False
    assert _settings(environment="test").is_production_like() is False


def test_flags_known_placeholder_secrets():
    s = _settings(mongo_password="changeme", system_password="secret")
    flagged = s.insecure_default_warnings()
    assert "MONGO_PASSWORD" in flagged
    assert "SYSTEM_PASSWORD" in flagged


def test_ignores_strong_secrets_and_unset():
    s = _settings(mongo_password="a-strong-random-value", system_password=None)
    assert s.insecure_default_warnings() == []


def test_placeholder_check_is_case_insensitive():
    assert "MONGO_PASSWORD" in _settings(mongo_password="ChangeMe").insecure_default_warnings()
