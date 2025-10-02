from pathlib import Path

import pytest

from launchpad.artifacts.android.aab import AAB
from launchpad.artifacts.android.apk import APK
from launchpad.artifacts.android.zipped_aab import ZippedAAB
from launchpad.artifacts.android.zipped_apk import ZippedAPK
from launchpad.artifacts.apple.zipped_xcarchive import ZippedXCArchive
from launchpad.artifacts.artifact_factory import ArtifactFactory


def test_factory_creates_aab(hn_aab: Path) -> None:
    """Test that factory creates AAB for .aab files."""
    artifact = ArtifactFactory.from_path(hn_aab)
    assert isinstance(artifact, AAB)


def test_factory_creates_zipped_aab(zipped_aab: Path) -> None:
    """Test that factory creates ZippedAAB for zipped .aab files."""
    artifact = ArtifactFactory.from_path(zipped_aab)
    assert isinstance(artifact, ZippedAAB)


def test_factory_creates_apk(hn_apk: Path) -> None:
    """Test that factory creates APK for .apk files."""
    artifact = ArtifactFactory.from_path(hn_apk)
    assert isinstance(artifact, APK)


def test_factory_creates_zipped_apk(zipped_apk: Path) -> None:
    """Test that factory creates ZippedAPK for zipped .apk files."""
    artifact = ArtifactFactory.from_path(zipped_apk)
    assert isinstance(artifact, ZippedAPK)


def test_factory_creates_xcarchive(hackernews_xcarchive: Path) -> None:
    """Test that factory creates ZippedXCArchive for .xcarchive.zip files."""
    artifact = ArtifactFactory.from_path(hackernews_xcarchive)
    assert isinstance(artifact, ZippedXCArchive)


def test_factory_raises_file_not_found(tmp_path: Path) -> None:
    """Test that factory raises FileNotFoundError for non-existent files."""
    with pytest.raises(FileNotFoundError):
        ArtifactFactory.from_path(tmp_path / "nonexistent.apk")


def test_factory_raises_value_error_for_invalid_file(tmp_path: Path) -> None:
    """Test that factory raises ValueError for invalid artifact files."""
    invalid_file = tmp_path / "invalid.txt"
    invalid_file.write_text("This is not a valid artifact")

    with pytest.raises(ValueError, match="Input is not a supported artifact"):
        ArtifactFactory.from_path(invalid_file)
