from pathlib import Path
from unittest.mock import patch

import pytest

from launchpad.artifacts.android.aab import AAB
from launchpad.artifacts.android.manifest.manifest import AndroidApplication, AndroidManifest
from launchpad.artifacts.providers.exceptions import UnsafePathError


@pytest.fixture
def test_aab(hn_aab: Path) -> AAB:
    return AAB(hn_aab)


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

    def test_universal_apk(self, test_aab: AAB, tmpdir) -> None:
        assert test_aab.get_universal_apk(Path(tmpdir)) is not None

    def test_get_app_icon(self, test_aab: AAB) -> None:
        icon = test_aab.get_app_icon()

        assert icon is not None
        assert len(icon) > 0
        assert icon.startswith(b"\x89PNG")
        assert icon.endswith(b"IEND\xae\x42\x60\x82")

    def test_get_app_icon_rejects_path_traversal(self, test_aab: AAB) -> None:
        malicious_app = AndroidApplication.model_construct(icon_path="../../../etc/passwd")
        malicious_manifest = AndroidManifest.model_construct(application=malicious_app)
        with patch.object(test_aab, "get_manifest", return_value=malicious_manifest):
            with pytest.raises(UnsafePathError):
                test_aab.get_app_icon()

    def test_get_dex_mapping_caches_mapping(self, test_aab: AAB) -> None:
        dex_mapping = test_aab.get_dex_mapping()

        assert dex_mapping is not None
        assert test_aab.get_dex_mapping() is dex_mapping
