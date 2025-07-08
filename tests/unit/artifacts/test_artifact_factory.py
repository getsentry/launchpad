import zipfile

from pathlib import Path

import pytest

from launchpad.artifacts.android.aab import AAB
from launchpad.artifacts.android.apk import APK
from launchpad.artifacts.android.zipped_aab import ZippedAAB
from launchpad.artifacts.android.zipped_apk import ZippedAPK
from launchpad.artifacts.apple.zipped_xcarchive import ZippedXCArchive
from launchpad.artifacts.artifact_factory import ArtifactFactory


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

    with pytest.raises(ValueError, match="Input is not a supported artifact"):
        ArtifactFactory.from_path(invalid_file)


def test_factory_rejects_empty_zip(tmp_path: Path) -> None:
    """Test that factory rejects completely empty zip files."""
    empty_zip = tmp_path / "empty.zip"
    with zipfile.ZipFile(empty_zip, "w"):
        pass  # Create empty zip

    with pytest.raises(ValueError, match="Input is not a supported artifact"):
        ArtifactFactory.from_path(empty_zip)


def test_factory_rejects_zip_with_only_empty_folders(tmp_path: Path) -> None:
    """Test that factory rejects zip files with only empty directories."""
    zip_with_folders = tmp_path / "empty_folders.zip"
    with zipfile.ZipFile(zip_with_folders, "w") as zf:
        # Add empty directories
        zf.writestr("Products/", "")
        zf.writestr("Applications/", "")
        zf.writestr("dSYMs/", "")

    with pytest.raises(ValueError, match="Input is not a supported artifact"):
        ArtifactFactory.from_path(zip_with_folders)


def test_factory_rejects_xcarchive_missing_info_plist(tmp_path: Path) -> None:
    """Test that factory rejects XCArchive-like structure missing Info.plist."""
    malformed_xcarchive = tmp_path / "no_info_plist.zip"
    with zipfile.ZipFile(malformed_xcarchive, "w") as zf:
        # Has Products/Applications structure but missing Info.plist
        zf.writestr("Products/Applications/MyApp.app/MyApp", "fake binary")
        zf.writestr("Products/Applications/MyApp.app/some_file.txt", "content")

    with pytest.raises(ValueError, match="Input is not a supported artifact"):
        ArtifactFactory.from_path(malformed_xcarchive)


def test_factory_rejects_xcarchive_missing_products_structure(tmp_path: Path) -> None:
    """Test that factory rejects zip with Info.plist but no Products/Applications structure."""
    malformed_xcarchive = tmp_path / "no_products.zip"
    with zipfile.ZipFile(malformed_xcarchive, "w") as zf:
        # Has Info.plist but wrong structure
        zf.writestr("Info.plist", "<?xml version='1.0'?><plist></plist>")
        zf.writestr("SomeOtherFolder/MyApp.app/MyApp", "fake binary")

    with pytest.raises(ValueError, match="Input is not a supported artifact"):
        ArtifactFactory.from_path(malformed_xcarchive)
