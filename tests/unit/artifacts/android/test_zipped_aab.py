from pathlib import Path

import pytest

from launchpad.artifacts.android.zipped_aab import ZippedAAB


@pytest.fixture
def test_zipped_aab_path() -> Path:
    return Path("tests/_fixtures/android/zipped_aab.zip")


@pytest.fixture
def test_zipped_aab(test_zipped_aab_path: Path) -> ZippedAAB:
    with open(test_zipped_aab_path, "rb") as f:
        return ZippedAAB(test_zipped_aab_path, f.read())


class TestZippedAAB:
    def test_get_manifest(self, test_zipped_aab: ZippedAAB) -> None:
        """Test parsing valid ZippedAAB manifest returns the primary AAB manifest."""
        manifest = test_zipped_aab.get_manifest().model_dump()

        assert manifest["version_code"] == "13"
        assert manifest["version_name"] == "1.0.2"
        assert manifest["application"]["label"] == "Hacker News"
        assert manifest["application"]["icon_path"] == "res/mipmap-anydpi-v26/ic_launcher.xml"
        assert manifest["package_name"] == "com.emergetools.hackernews"
