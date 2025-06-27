from pathlib import Path

import pytest

from launchpad.artifacts.android.aab import AAB


@pytest.fixture
def test_aab_path() -> Path:
    return Path("tests/_fixtures/android/hn.aab")


@pytest.fixture
def test_aab(test_aab_path: Path) -> AAB:
    return AAB(test_aab_path)


class TestAAB:
    def test_get_manifest(self, test_aab: AAB) -> None:
        """Test parsing valid AAB manifest."""
        """Implicitly tests that the resource table is parsed correctly with correct values of label and icon_path"""
        manifest = test_aab.get_manifest().model_dump()

        assert manifest["version_code"] == "13"
        assert manifest["version_name"] == "1.0.2"
        assert manifest["application"]["label"] == "Hacker News"
        assert manifest["application"]["icon_path"] == "res/mipmap-anydpi-v26/ic_launcher.xml"
        assert manifest["package_name"] == "com.emergetools.hackernews"
