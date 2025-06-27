from pathlib import Path

import pytest

from launchpad.artifacts.android.apk import APK


@pytest.fixture
def test_apk_path() -> Path:
    return Path("tests/_fixtures/android/hn.apk")


@pytest.fixture
def test_apk(test_apk_path: Path) -> APK:
    return APK(test_apk_path)


class TestAPK:
    def test_get_manifest(self, test_apk: APK) -> None:
        """Test parsing valid APK manifest."""
        """Implicitly tests that the resource table is parsed correctly with correct values of label and icon_path"""
        manifest = test_apk.get_manifest().model_dump()

        assert manifest["version_code"] == "13"
        assert manifest["version_name"] == "1.0.2"
        assert manifest["application"]["label"] == "Hacker News"
        assert manifest["application"]["icon_path"] == "res/BW.xml"
        assert manifest["package_name"] == "com.emergetools.hackernews"
