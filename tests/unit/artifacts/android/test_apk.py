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
