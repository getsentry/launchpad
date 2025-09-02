import zipfile

from pathlib import Path

import pytest

from launchpad.artifacts.android.apk import APK


@pytest.fixture
def test_apk_path() -> Path:
    return Path("tests/_fixtures/android/hn.apk")


@pytest.fixture
def debug_apk_path() -> Path:
    return Path("tests/_fixtures/android/debug.apk")


def extract_classes_dex_from_apk(apk_path: Path) -> bytes:
    with zipfile.ZipFile(apk_path, "r") as zf:
        with zf.open("classes.dex") as dex_file:
            return dex_file.read()


def test_parse_dex_from_hn_apk(test_apk_path):
    apk = APK(test_apk_path)
    classes = apk.get_class_definitions()

    assert len(classes) == 4755


def test_parse_dex_from_debug_apk(debug_apk_path):
    apk = APK(debug_apk_path)
    classes = apk.get_class_definitions()

    assert len(classes) == 14950
