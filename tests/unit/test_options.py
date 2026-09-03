from sentry_options.testing import override_options

import launchpad.options as options

from launchpad.options import get_option


def test_get_option_returns_schema_default():
    assert get_option("projects.skip", ["fallback"]) == []


def test_get_option_returns_fallback_when_init_fails(monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("init failed")

    monkeypatch.setattr(options, "_init_ok", None)
    monkeypatch.setattr(options.sentry_options, "init", boom)

    assert get_option("projects.skip", ["fallback"]) == ["fallback"]


def test_get_option_returns_overridden_value():
    with override_options("launchpad", {"projects.skip": ["123", "456"]}):
        assert get_option("projects.skip", []) == ["123", "456"]


def test_get_option_returns_fallback_for_unknown_option():
    assert get_option("does.not.exist", "fallback") == "fallback"
