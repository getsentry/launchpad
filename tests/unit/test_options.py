from sentry_options.testing import override_options

from launchpad.options import get_option


def test_get_option_returns_schema_default():
    assert get_option("projects.skip", ["fallback"]) == []


def test_get_option_returns_overridden_value():
    with override_options("launchpad", {"projects.skip": ["123", "456"]}):
        assert get_option("projects.skip", []) == ["123", "456"]


def test_get_option_returns_fallback_for_unknown_option():
    assert get_option("does.not.exist", "fallback") == "fallback"
