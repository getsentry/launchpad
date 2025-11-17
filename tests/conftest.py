import os

from pathlib import Path

import pytest

from launchpad.artifacts.apple.zipped_xcarchive import ZippedXCArchive


@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    """Set up test environment variables for all tests."""
    os.environ.setdefault("LAUNCHPAD_ENV", "TEST")


@pytest.fixture(scope="session")
def fixtures_root() -> Path:
    """Root directory for test fixtures."""
    return Path(__file__).parent / "_fixtures"


# iOS fixtures
@pytest.fixture(scope="session")
def hackernews_xcarchive(fixtures_root: Path) -> Path:
    """HackerNews.xcarchive.zip test fixture."""
    return fixtures_root / "ios" / "HackerNews.xcarchive.zip"


@pytest.fixture(scope="session")
def hackernews_xcarchive_obj(hackernews_xcarchive: Path) -> ZippedXCArchive:
    return ZippedXCArchive(hackernews_xcarchive)


@pytest.fixture(scope="session")
def hackernews_without_parsed_assets(fixtures_root: Path) -> Path:
    """HackerNews without parsed assets test fixture."""
    return fixtures_root / "ios" / "HackerNews_without_parsedassets.xcarchive.zip"


@pytest.fixture(scope="session")
def sentry_ios_archive(fixtures_root: Path) -> Path:
    """Sentry iOS archive test fixture."""
    return fixtures_root / "ios" / "Sentry-ios-arm64_arm64e.zip"


@pytest.fixture(scope="session")
def hackernews_results_json(fixtures_root: Path) -> Path:
    """HackerNews results JSON test fixture."""
    return fixtures_root / "ios" / "hackernews-results.json"


# Android fixtures
@pytest.fixture(scope="session")
def debug_apk(fixtures_root: Path) -> Path:
    """Debug APK test fixture."""
    return fixtures_root / "android" / "debug.apk"


@pytest.fixture(scope="session")
def hn_apk(fixtures_root: Path) -> Path:
    """HackerNews APK test fixture."""
    return fixtures_root / "android" / "hn.apk"


@pytest.fixture(scope="session")
def hn_aab(fixtures_root: Path) -> Path:
    """HackerNews AAB test fixture."""
    return fixtures_root / "android" / "hn.aab"


@pytest.fixture(scope="session")
def hn_optimizable_apk(fixtures_root: Path) -> Path:
    """HackerNews APK with optimizable image test fixture."""
    return fixtures_root / "android" / "hn-with-optimizeable-image.apk"


@pytest.fixture(scope="session")
def zipped_aab(fixtures_root: Path) -> Path:
    """Zipped AAB test fixture."""
    return fixtures_root / "android" / "zipped_aab.zip"


@pytest.fixture(scope="session")
def zipped_apk(fixtures_root: Path) -> Path:
    """Zipped APK test fixture."""
    return fixtures_root / "android" / "zipped_apk.zip"


# Hermes fixtures
@pytest.fixture(scope="session")
def hermes_test_hbc(fixtures_root: Path) -> Path:
    """Hermes test HBC file fixture."""
    return fixtures_root / "hermes" / "test.hbc"
