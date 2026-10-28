"""Configuration regression tests for production authentication."""
import json
import pytest


def test_production_rejects_missing_credentials(monkeypatch):
    from main import _load_api_keys
    monkeypatch.setenv("OMNIGUARD_ENV", "production")
    monkeypatch.delenv("OMNIGUARD_API_KEYS_JSON", raising=False)
    with pytest.raises(RuntimeError, match="requires"):
        _load_api_keys()


def test_production_accepts_configured_credentials(monkeypatch):
    from main import _load_api_keys
    monkeypatch.setenv("OMNIGUARD_ENV", "production")
    key = "test-configured-key-long-enough-123"
    monkeypatch.setenv("OMNIGUARD_API_KEYS_JSON", json.dumps({
        key: {"id": "service", "scopes": ["chat"], "type": "service"}
    }))
    assert _load_api_keys()[key]["id"] == "service"


def test_rejects_short_keys(monkeypatch):
    from main import _load_api_keys
    monkeypatch.setenv("OMNIGUARD_API_KEYS_JSON", json.dumps({
        "short": {"id": "service", "scopes": ["chat"]}
    }))
    with pytest.raises(RuntimeError, match="Invalid"):
        _load_api_keys()
