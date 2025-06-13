from pathlib import Path

import pytest

from launchpad.artifacts.android.aab import AAB
from launchpad.artifacts.android.apk import APK
from launchpad.artifacts.android.zipped_aab import ZippedAAB
from launchpad.artifacts.android.zipped_apk import ZippedAPK
from launchpad.artifacts.artifact_factory import ArtifactFactory
from launchpad.artifacts.ios.zipped_xcarchive import ZippedXCArchive


@pytest.fixture
def fixtures_dir() -> Path:
    return Path("tests/_fixtures/")


@pytest.fixture
def android_fixtures(fixtures_dir: Path) -> dict[str, Path]:
    android_dir = fixtures_dir / "android"
    return {
        "aab": android_dir / "hn.aab",
        "zipped_aab": android_dir / "zipped_aab.zip",
        "apk": android_dir / "hn.apk",
        "zipped_apk": android_dir / "zipped_apk.zip",
    }


@pytest.fixture
def ios_fixtures(fixtures_dir: Path) -> dict[str, Path]:
    ios_dir = fixtures_dir / "ios"
    return {
        "xcarchive": ios_dir / "HackerNews.xcarchive.zip",
    }


def test_factory_creates_aab(android_fixtures: dict[str, Path]) -> None:
    """Test that factory creates AAB for .aab files."""
    artifact = ArtifactFactory.from_path(android_fixtures["aab"])
    assert isinstance(artifact, AAB)


def test_factory_creates_zipped_aab(android_fixtures: dict[str, Path]) -> None:
    """Test that factory creates ZippedAAB for zipped .aab files."""
    artifact = ArtifactFactory.from_path(android_fixtures["zipped_aab"])
    assert isinstance(artifact, ZippedAAB)


def test_factory_creates_apk(android_fixtures: dict[str, Path]) -> None:
    """Test that factory creates APK for .apk files."""
    artifact = ArtifactFactory.from_path(android_fixtures["apk"])
    assert isinstance(artifact, APK)


def test_factory_creates_zipped_apk(android_fixtures: dict[str, Path]) -> None:
    """Test that factory creates ZippedAPK for zipped .apk files."""
    artifact = ArtifactFactory.from_path(android_fixtures["zipped_apk"])
    assert isinstance(artifact, ZippedAPK)


def test_factory_creates_xcarchive(ios_fixtures: dict[str, Path]) -> None:
    """Test that factory creates ZippedXCArchive for .xcarchive.zip files."""
    artifact = ArtifactFactory.from_path(ios_fixtures["xcarchive"])
    assert isinstance(artifact, ZippedXCArchive)


def test_factory_raises_file_not_found(tmp_path: Path) -> None:
    """Test that factory raises FileNotFoundError for non-existent files."""
    with pytest.raises(FileNotFoundError):
        ArtifactFactory.from_path(tmp_path / "nonexistent.apk")


def test_factory_raises_value_error_for_invalid_file(tmp_path: Path) -> None:
    """Test that factory raises ValueError for invalid artifact files."""
    invalid_file = tmp_path / "invalid.txt"
    invalid_file.write_text("This is not a valid artifact")

    with pytest.raises(ValueError, match="File is not a supported Android artifact"):
        ArtifactFactory.from_path(invalid_file)
