from pathlib import Path
from unittest.mock import patch

import pytest

from launchpad.artifacts.android.apk import APK
from launchpad.artifacts.android.manifest.manifest import AndroidApplication, AndroidManifest
from launchpad.artifacts.providers.zip_provider import UnsafePathError


@pytest.fixture
def test_apk(hn_apk: Path) -> APK:
    return APK(hn_apk)


class TestAPK:
    def test_get_manifest(self, test_apk: APK) -> None:
        """Implicitly tests that the resource table is parsed correctly with correct values of label and icon_path"""
        manifest = test_apk.get_manifest().model_dump()

        assert manifest["version_code"] == "13"
        assert manifest["version_name"] == "1.0.2"
        assert manifest["application"]["label"] == "Hacker News"
        assert manifest["application"]["icon_path"] == "res/BW.xml"
        assert manifest["package_name"] == "com.emergetools.hackernews"

    def test_get_class_definitions(self, test_apk: APK) -> None:
        class_definitions = test_apk.get_class_definitions()

        assert len(class_definitions) == 4755
        assert class_definitions[0].fqn() == "android.app.ServiceStartNotAllowedException"
        assert class_definitions[-1].fqn() == "retrofit2.http.Url"

    def test_get_apksigner_certs(self, test_apk: APK) -> None:
        certs = test_apk.get_apksigner_certs()

        assert (
            certs
            == "Signer #1 certificate DN: C=US, O=Android, CN=Android Debug\nSigner #1 certificate SHA-256 digest: d7f26fa0583723aa59bf83791d9fdeac19a854ffed2cecb6f29885c05b48c6ca\nSigner #1 certificate SHA-1 digest: e96562a30912cf28129a7f5bfea234c549304228\nSigner #1 certificate MD5 digest: d2619cb1d0738719f3a2d69b4af93237\n"
        )

    def test_get_app_icon(self, test_apk: APK) -> None:
        icon = test_apk.get_app_icon()

        assert icon is not None
        assert len(icon) > 0
        assert icon.startswith(b"\x89PNG")
        assert icon.endswith(b"IEND\xae\x42\x60\x82")

    def test_get_app_icon_rejects_path_traversal(self, test_apk: APK) -> None:
        malicious_app = AndroidApplication.model_construct(icon_path="../../../etc/passwd")
        malicious_manifest = AndroidManifest.model_construct(application=malicious_app)
        with patch.object(test_apk, "get_manifest", return_value=malicious_manifest):
            with pytest.raises(UnsafePathError):
                test_apk.get_app_icon()
