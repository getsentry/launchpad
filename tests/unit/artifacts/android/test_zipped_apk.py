from pathlib import Path

import pytest

from launchpad.artifacts.android.zipped_apk import ZippedAPK


@pytest.fixture
def test_zipped_apk_path() -> Path:
    return Path("tests/_fixtures/android/zipped_apk.zip")


@pytest.fixture
def test_zipped_apk(test_zipped_apk_path: Path) -> ZippedAPK:
    return ZippedAPK(test_zipped_apk_path)


class TestZippedAPK:
    def test_get_manifest(self, test_zipped_apk: ZippedAPK) -> None:
        """Test parsing valid ZippedAPK manifest returns the primary APK manifest."""
        manifest = test_zipped_apk.get_manifest().model_dump()

        assert manifest["version_code"] == "13"
        assert manifest["version_name"] == "1.0.2"
        assert manifest["application"]["label"] == "Hacker News"
        assert manifest["application"]["icon_path"] == "res/BW.xml"
        assert manifest["package_name"] == "com.emergetools.hackernews"
